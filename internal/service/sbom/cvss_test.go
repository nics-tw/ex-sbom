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
	require.Equal(t, RemediationElevated, assessFinding(findings[0], key.Version, new(RemediationThreshold), nil).Priority)

	advisory.Severity = []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"}}
	findings = packageFindings(packages, key)
	require.Len(t, findings, 1)
	require.Equal(t, "3.8", findings[0].CVSSScore)
	advisory.Severity = nil
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

func TestAliasGroupCVSSFallback(t *testing.T) {
	key := file.PackageVersion{Ecosystem: "npm", Name: "widget", Version: "1.0.0"}
	for _, tc := range []struct {
		name     string
		severity *osvschema.Severity
		score    string
		standard string
	}{
		{"CVSS 2.0", &osvschema.Severity{Type: osvschema.Severity_CVSS_V2, Score: "AV:N/AC:L/Au:N/C:C/I:C/A:C"}, "10.0", "2.0"},
		{"CVSS 3.0", &osvschema.Severity{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "9.8", "3.0"},
		{"CVSS 3.1", &osvschema.Severity{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "9.8", "3.1"},
		{"CVSS 4.0", &osvschema.Severity{Type: osvschema.Severity_CVSS_V4, Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"}, "10.0", "4.0"},
		{"version unknown", &osvschema.Severity{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "8.5", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const scannedID = "TEST-PRIMARY"
			const aliasID = "CVE-2025-1234"
			pkg := models.PackageVulns{
				Vulnerabilities: []*osvschema.Vulnerability{
					{Id: scannedID, Aliases: []string{aliasID}},
					{Id: aliasID, Severity: []*osvschema.Severity{tc.severity}},
				},
				Groups: []models.GroupInfo{{IDs: []string{scannedID, aliasID}, MaxSeverity: tc.score}},
			}
			for _, findings := range [][]Vuln{
				packageFindings(map[file.PackageVersion]models.PackageVulns{key: pkg}, key),
				buildVulns(pkg, key.Version, nil),
			} {
				require.Len(t, findings, 2)
				require.Equal(t, tc.score, findings[0].CVSSScore)
				require.Equal(t, tc.standard, findings[0].CVSSVersion)
			}
		})
	}
}
