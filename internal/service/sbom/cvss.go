// SPDX-License-Identifier: MIT

package ssbom

import (
	"strconv"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	cvss20 "github.com/pandatix/go-cvss/20"
	cvss30 "github.com/pandatix/go-cvss/30"
	cvss31 "github.com/pandatix/go-cvss/31"
	cvss40 "github.com/pandatix/go-cvss/40"
)

func advisoryCVSS(v *osvschema.Vulnerability) (string, string) {
	best := -1.0
	var version string
	for _, severity := range v.GetSeverity() {
		score, standard := vectorScore(severity)
		if standard != "" && (score > best || (score == best && standard > version)) {
			best, version = score, standard
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
