// SPDX-License-Identifier: MIT

package ssbom

import (
	"strconv"
	"strings"

	"ex-sbom/util/file"
	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	cvss20 "github.com/pandatix/go-cvss/20"
	cvss30 "github.com/pandatix/go-cvss/30"
	cvss31 "github.com/pandatix/go-cvss/31"
	cvss40 "github.com/pandatix/go-cvss/40"
)

func advisoryCVSS(v *osvschema.Vulnerability, identity *file.PackageVersion) (string, string) {
	best := -1.0
	var version string
	consider := func(severities []*osvschema.Severity) {
		for _, severity := range severities {
			score, standard := vectorScore(severity)
			if standard != "" && (score > best || (score == best && standard > version)) {
				best, version = score, standard
			}
		}
	}
	consider(v.GetSeverity())
	if version == "" && identity != nil && identity.Name != "" {
		ecosystem, err := osvecosystem.Parse(identity.Ecosystem)
		if err == nil && !ecosystem.IsEmpty() {
			for _, affected := range v.GetAffected() {
				pkg := affected.GetPackage()
				if pkg.GetName() != identity.Name {
					continue
				}
				affectedEcosystem, err := osvecosystem.Parse(pkg.GetEcosystem())
				if err == nil && ecosystem.Equal(affectedEcosystem) {
					consider(affected.GetSeverity())
				}
			}
		}
	}
	if version == "" {
		return "", ""
	}
	return strconv.FormatFloat(best, 'f', 1, 64), version
}

func vectorScore(severity *osvschema.Severity) (float64, string) {
	value := severity.GetScore()
	switch severity.GetType() {
	case osvschema.Severity_CVSS_V2:
		if v, err := cvss20.ParseVector(value); err == nil {
			return v.BaseScore(), "2.0"
		}
	case osvschema.Severity_CVSS_V3:
		if strings.HasPrefix(value, "CVSS:3.0/") {
			if v, err := cvss30.ParseVector(value); err == nil {
				return v.BaseScore(), "3.0"
			}
		}
		if strings.HasPrefix(value, "CVSS:3.1/") {
			if v, err := cvss31.ParseVector(value); err == nil {
				return v.BaseScore(), "3.1"
			}
		}
	case osvschema.Severity_CVSS_V4:
		if v, err := cvss40.ParseVector(value); err == nil {
			return v.Score(), "4.0"
		}
	}
	return 0, ""
}
