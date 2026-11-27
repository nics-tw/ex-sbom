// SPDX-License-Identifier: MIT

package ssbom

import (
	goversion "go/version"
	"strings"

	"ex-sbom/util/file"

	depssemver "deps.dev/util/semver"
	"golang.org/x/mod/semver"
)

// InstalledVersionEvidence records the scanner identity even when the
// declaration conflicts. Confirmed is set only during SBOM analysis.
type InstalledVersionEvidence struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version"`
	Confirmed bool   `json:"confirmed"`
}

func scannedInstalledVersion(scanned file.PackageVersion, declarations ...string) *InstalledVersionEvidence {
	version := usableVersion(scanned.Version)
	if scanned.Name == "" || scanned.Ecosystem == "" || version == "" {
		return nil
	}
	confirmed := sameInstalledVersion(scanned.Ecosystem, version, version)
	for _, v := range declarations {
		if v = usableVersion(v); v != "" && !sameInstalledVersion(scanned.Ecosystem, v, version) {
			confirmed = false
		}
	}
	return &InstalledVersionEvidence{Ecosystem: scanned.Ecosystem, Package: scanned.Name, Version: version, Confirmed: confirmed}
}

func usableVersion(v string) string {
	v = strings.TrimSpace(v)
	switch strings.ToUpper(v) {
	case "NOASSERTION", "NONE", "UNKNOWN", "UNSPECIFIED", "N/A", "*", "-", "?":
		return ""
	default:
		return v
	}
}

func sameInstalledVersion(ecosystem, a, b string) bool {
	if ecosystem == "PyPI" {
		// The parser also accepts infinity as a range boundary.
		if strings.ContainsRune(a, '∞') || strings.ContainsRune(b, '∞') {
			return false
		}
		installed, err := depssemver.PyPI.Parse(a)
		if err != nil || installed.IsWildcard() {
			return false
		}
		if a == b {
			return true
		}
		other, err := depssemver.PyPI.Parse(b)
		return err == nil && !other.IsWildcard() && strings.EqualFold(installed.Canon(true), other.Canon(true))
	}
	switch ecosystem {
	case "Go", "npm", "crates.io":
		if ecosystem == "Go" && a == b && goversion.IsValid(a) {
			return true
		}
		// Compare normalized identity including build metadata, not precedence.
		a, b = repairVersion(a), repairVersion(b)
		if a != b {
			return false
		}
		canonical := semver.Canonical(a)
		// The Go parser accepts short versions that represent ranges in npm and Cargo.
		return canonical != "" && (ecosystem == "Go" || canonical == strings.TrimSuffix(a, semver.Build(a)))
	default:
		return a == b
	}
}

// ConfirmedInstalledVersion returns the matched version stored with this
// analysis. Older records with just a display version need a rescan.
func (component Component) ConfirmedInstalledVersion() string {
	evidence := component.InstalledVersion
	if evidence == nil || !evidence.Confirmed || evidence.Package == "" || evidence.Ecosystem == "" {
		return ""
	}
	v := usableVersion(evidence.Version)
	if !sameInstalledVersion(evidence.Ecosystem, v, v) {
		return ""
	}
	return v
}
