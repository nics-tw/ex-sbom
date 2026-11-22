// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package file

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

// here mimic and import the way osv-scanner/v2 scan the vulnerability
// TODO: refactor to scan directly if possible
func GetScanResult(localPath string) (map[PackageVersion]models.PackageVulns, QueryObservation, error) {
	transport := &scanTransport{base: http.DefaultTransport, seen: make(map[osvRequest]osvResponse)}
	scannerAction := osvscanner.ScannerActions{
		SBOMPaths: []string{localPath},
		ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
			HTTPClient: &http.Client{
				Transport:     transport,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			},
		},
		CallAnalysisStates: map[string]bool{
			"go":   true,
			"rust": false,
		},
	}

	result, err := osvscanner.DoScan(scannerAction)
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		return nil, QueryObservation{}, err
	}

	// The scanner can log enrichment failures without returning them.
	observation, err := transport.observation()
	if err != nil {
		return nil, QueryObservation{}, err
	}
	findings := make(map[PackageVersion]models.PackageVulns)
	for _, source := range result.Results {
		for _, pkg := range source.Packages {
			if len(pkg.Vulnerabilities) == 0 || pkg.Package.Inventory == nil {
				continue
			}
			info := pkg.Package.Inventory
			key := packageIdentity(info.Name, info.Version, info.Ecosystem().String(), info.PURL())
			if key.Name != "" {
				findings[key] = pkg
			}
		}
	}
	return findings, observation, nil
}

// IdentifyPackage matches an uploaded package and the scanner's findings by
// ecosystem, scoped name and version. Unsupported identities stay unmatched.
func IdentifyPackage(name, version, locator string) PackageVersion {
	p, err := purl.FromString(locator)
	if err != nil {
		return PackageVersion{}
	}
	info := extractor.Package{PURLType: p.Type}
	return packageIdentity(name, version, info.Ecosystem().String(), &p)
}

func packageIdentity(name, version, ecosystem string, p *purl.PackageURL) PackageVersion {
	if p == nil || ecosystem == "" {
		return PackageVersion{}
	}
	if name == "" {
		name = p.Name
	}
	if version == "" {
		version = p.Version
	}
	if name == "" || version == "" {
		return PackageVersion{}
	}
	if ecosystem == "PyPI" {
		name = normalizePythonName(name)
	} else if p.Namespace != "" {
		separator := "/"
		if p.Type == purl.TypeMaven {
			separator = ":"
		}
		prefix := p.Namespace + separator
		if !strings.HasPrefix(name, prefix) {
			name = prefix + name
		}
	}
	if ecosystem == "Go" && name == "go" {
		name = "stdlib"
	}
	return PackageVersion{Ecosystem: ecosystem, Name: name, Version: version}
}

func normalizePythonName(name string) string {
	var normalized strings.Builder
	lastSeparator := false
	for _, char := range strings.ToLower(name) {
		if strings.ContainsRune("-_.", char) {
			if !lastSeparator {
				normalized.WriteByte('-')
			}
			lastSeparator = true
			continue
		}
		normalized.WriteRune(char)
		lastSeparator = false
	}
	return normalized.String()
}
