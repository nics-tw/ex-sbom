//go:build unit

package ssbom

import (
	"testing"

	"ex-sbom/util/file"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/require"
)

func TestAdvisoryCVSS(t *testing.T) {
	v := &osvschema.Vulnerability{Severity: []*osvschema.Severity{
		{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{Type: osvschema.Severity_CVSS_V4, Score: "invalid"},
	}}
	score, standard := advisoryCVSS(v, nil)
	require.Equal(t, "9.8", score)
	require.Equal(t, "3.1", standard)
}

func TestPackageFindingsUseMatchingAffectedCVSS(t *testing.T) {
	const (
		high = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
		max  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	)
	key := file.IdentifyPackage("widget", "1.0.0", "pkg:npm/%40team/widget@1.0.0")
	require.Equal(t, file.PackageVersion{Ecosystem: "npm", Name: "@team/widget", Version: "1.0.0"}, key)
	advisory := &osvschema.Vulnerability{
		Id: "TEST-ADVISORY",
		Affected: []*osvschema.Affected{
			{
				Package:  &osvschema.Package{Ecosystem: "npm", Name: "@other/widget", Purl: "pkg:npm/%40other/widget"},
				Severity: []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: max}},
			},
			{
				Package:  &osvschema.Package{Ecosystem: "Go", Name: "@team/widget"},
				Severity: []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: max}},
			},
			{
				Package:  &osvschema.Package{Ecosystem: "npm", Name: "@team/widget"},
				Severity: []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: high}},
			},
		},
	}
	packages := map[file.PackageVersion]models.PackageVulns{
		key: {Vulnerabilities: []*osvschema.Vulnerability{advisory}},
	}
	findings := packageFindings(packages, key)
	require.Len(t, findings, 1)
	require.Equal(t, "8.8", findings[0].CVSSScore)
	require.Equal(t, "3.1", findings[0].CVSSVersion)
	findings[0].EPSS = "0.20"
	require.Equal(t, RemediationElevated, assessFinding(findings[0], key.Version, new(RemediationThreshold)).Priority)

	advisory.Affected = advisory.Affected[:2]
	findings = packageFindings(packages, key)
	require.Len(t, findings, 1)
	require.Empty(t, findings[0].CVSSScore)
	require.Empty(t, findings[0].CVSSVersion)
}

func TestAdvisoryCVSSRespectsEcosystemRelease(t *testing.T) {
	v := &osvschema.Vulnerability{Affected: []*osvschema.Affected{
		{
			Package:  &osvschema.Package{Ecosystem: "Debian:11", Name: "widget"},
			Severity: []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		},
		{
			Package:  &osvschema.Package{Ecosystem: "Debian", Name: "widget"},
			Severity: []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}},
		},
	}}
	score, standard := advisoryCVSS(v, &file.PackageVersion{Ecosystem: "Debian:12", Name: "widget"})
	require.Equal(t, "8.8", score)
	require.Equal(t, "3.1", standard)
}
