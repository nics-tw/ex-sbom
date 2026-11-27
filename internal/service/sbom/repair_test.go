//go:build unit

package ssbom

import (
	"testing"

	"ex-sbom/util/file"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/require"
)

func TestVerifiedRepair(t *testing.T) {
	makeFinding := func(id, cvss, fixed string) Vuln {
		return Vuln{ID: id, CVSSScore: cvss, CVEIDs: []string{id}, RepairEvidence: &RepairEvidence{
			AdvisoryID: id, Ecosystem: "npm", Package: "body-parser", Installed: "1.19.0",
			Ranges: []RepairInterval{{Start: "0", Fixed: fixed}},
		}}
	}
	early := makeFinding("CVE-2024-45590", "8.7", "1.20.3")
	late := makeFinding("CVE-2025-99999", "7.5", "1.20.9")
	urgent := makeFinding("CVE-2024-99999", "6.5", "2.0.0")
	urgent.KEV, urgent.KEVCVE = KEVListed, urgent.ID
	component := Component{Name: "body-parser", Version: "1.19.0", InstalledVersion: confirmedVersion("npm", "body-parser", "1.19.0"), Vulns: []Vuln{early, late, urgent}}
	bom := FormattedSBOM{ComponentInfo: map[string]Component{"a": component, "b": component}}
	rows := bom.RemediationAssessments(nil)
	require.Equal(t, "1.20.9", rows[0].Upgrade)
	require.Equal(t, 2, rows[0].Covered)
	require.Equal(t, 0, rows[0].CumulativeFullyCoveredCVEs)
	require.Equal(t, 2, rows[1].CumulativeFullyCoveredCVEs)
	require.Equal(t, []string{urgent.ID}, rows[0].ResidualUrgentCVEs)
	require.Equal(t, 2, rows[1].RemainingUrgent)

	early.RepairEvidence.Ranges = append(early.RepairEvidence.Ranges, RepairInterval{Start: "1.20.8", Fixed: "1.21.0"})
	rows = bom.RemediationAssessments(nil)
	require.Equal(t, "1.21.0", rows[0].Upgrade)

	early.RepairEvidence.Ranges[1].Fixed = "2.0.0"
	require.Empty(t, bom.RemediationAssessments(nil)[0].Upgrade)
	early.RepairEvidence.Ranges[1].Fixed = "1.21.0-rc.1"
	require.Empty(t, bom.RemediationAssessments(nil)[0].Upgrade)
}

func TestRepairCoverageUsesConfirmedInstalledEvidence(t *testing.T) {
	for _, kev := range []KEVStatus{KEVUnlisted, KEVUnknown} {
		for _, tc := range []struct {
			name, display, upgrade string
			evidence               *InstalledVersionEvidence
			covered                int
		}{
			{"conflict", "1.19.0", "", &InstalledVersionEvidence{Ecosystem: "npm", Package: "fixture", Version: "1.19.0"}, 0},
			{"confirmed PURL with placeholder display", "NOASSERTION", "1.20.3", &InstalledVersionEvidence{Ecosystem: "npm", Package: "fixture", Version: "1.19.0", Confirmed: true}, 1},
			{"legacy without evidence", "1.19.0", "1.20.3", nil, 1},
		} {
			t.Run(tc.name+"/"+string(kev), func(t *testing.T) {
				finding := Vuln{
					ID: "CVE-2026-1000", CVSSScore: "8.0", KEV: kev,
					SuggestFixVersion: "1.20.3",
					RepairEvidence: &RepairEvidence{
						Ecosystem: "npm", Package: "fixture", Installed: "1.19.0",
						Ranges: []RepairInterval{{Start: "0", Fixed: "1.20.3"}},
					},
				}
				bom := FormattedSBOM{ComponentInfo: map[string]Component{
					"fixture": {Name: "fixture", Version: tc.display, InstalledVersion: tc.evidence, Vulns: []Vuln{finding}},
				}}

				assessment := bom.RemediationAssessments(nil)[0]
				require.Equal(t, tc.upgrade, assessment.Upgrade)
				require.Equal(t, tc.covered, assessment.Covered)
				require.Equal(t, finding.SuggestFixVersion, assessment.Driver.Finding.SuggestFixVersion)
			})
		}
	}
}

func TestCompatibleRepairSeries(t *testing.T) {
	require.True(t, compatibleRepairSeries("v0.1.9", "v0.1.0"))
	require.False(t, compatibleRepairSeries("v0.2.0", "v0.1.0"))
	require.True(t, compatibleRepairSeries("v1.2.0", "v1.1.0"))
}

func TestMatchedRepairEvidence(t *testing.T) {
	identity := file.PackageVersion{Ecosystem: "npm", Name: "body-parser", Version: "1.19.0"}
	affected := &osvschema.Affected{
		Package: &osvschema.Package{Ecosystem: "npm", Name: "body-parser"},
		Ranges: []*osvschema.Range{{Type: osvschema.Range_SEMVER, Events: []*osvschema.Event{
			{Introduced: "0"}, {Fixed: "1.20.3"}, {Introduced: "1.20.8"}, {LastAffected: "1.20.9"},
		}}},
	}
	advisory := &osvschema.Vulnerability{Id: "CVE-2024-45590", Affected: []*osvschema.Affected{affected}}
	evidence := matchedRepairEvidence(advisory, identity)
	require.NotNil(t, evidence)
	require.True(t, evidence.affects("1.20.9"))
	require.False(t, evidence.affects("1.20.10"))
	identity.Name = "another-package"
	require.Nil(t, matchedRepairEvidence(advisory, identity))
}

func TestConservativeRepairEvidence(t *testing.T) {
	identity := file.PackageVersion{Ecosystem: "npm", Name: "example", Version: "1.2.3"}
	for _, tc := range []struct {
		name     string
		kind     osvschema.Range_Type
		start    string
		versions []string
	}{
		{name: "unknown range type", kind: osvschema.Range_Type(99), start: "0"},
		{name: "reversed range", kind: osvschema.Range_SEMVER, start: "1.2.5", versions: []string{"1.2.3"}},
		{name: "invalid explicit version", kind: osvschema.Range_SEMVER, start: "0", versions: []string{"invalid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			advisory := &osvschema.Vulnerability{
				Id: "TEST-1",
				Affected: []*osvschema.Affected{{
					Package:  &osvschema.Package{Ecosystem: identity.Ecosystem, Name: identity.Name},
					Versions: tc.versions,
					Ranges: []*osvschema.Range{{
						Type: tc.kind, Events: []*osvschema.Event{{Introduced: tc.start}, {Fixed: "1.2.4"}},
					}},
				}},
			}
			require.Nil(t, matchedRepairEvidence(advisory, identity))
		})
	}
}

func TestGoAdvisoryDisplayPreservesSnapshotData(t *testing.T) {
	finding := Vuln{SuggestFixVersion: "1.2.4, v2.0.0", OtherFixVersions: "not-a-version, 1.2.5", FixVersions: []string{"1.2.4", "v2.0.0"}}
	component := Component{Name: "example.com/widget", Version: "v1.2.3", Vulns: []Vuln{finding}}
	bom := FormattedSBOM{ComponentInfo: map[string]Component{"widget": component}}
	checksum := HashSBOM(bom)
	source := &ReportSource{GoComponents: map[string]bool{"widget": true}}
	bom.ReportSource = source
	require.Equal(t, checksum, HashSBOM(bom))
	require.True(t, IsGoComponent(source, "widget", component))
	require.False(t, IsGoComponent(source, "other", component))
	display := component.Vulns[0].GoAdvisoryDisplay()
	require.Equal(t, "v1.2.4, v2.0.0", display.SuggestFixVersion)
	require.Equal(t, "not-a-version, v1.2.5", display.OtherFixVersions)
	require.Equal(t, []string{"1.2.4", "v2.0.0"}, display.FixVersions)
	require.Equal(t, finding, component.Vulns[0])
	require.Empty(t, GoCandidateVersions(""))
	component.Vulns[0].RepairEvidence = &RepairEvidence{Ecosystem: "Go", Package: component.Name, Installed: "1.2.3"}
	require.True(t, IsGoComponent(nil, "widget", component))
	component.Vulns[0].RepairEvidence.Installed = "1.2.2"
	require.False(t, IsGoComponent(nil, "widget", component))
	component.Vulns[0].RepairEvidence = &RepairEvidence{Ecosystem: "npm", Package: component.Name, Installed: "1.2.3"}
	require.False(t, IsGoComponent(nil, "widget", component))
}

func TestRepairVersionUsesGoPrefixAndMatchingEvidence(t *testing.T) {
	const installed = "v1.2.3"
	newFinding := func(id, score, name, version string) Vuln {
		return Vuln{ID: id, CVSSScore: score, RepairEvidence: &RepairEvidence{
			AdvisoryID: id, Ecosystem: "Go", Package: name, Installed: version,
			Ranges: []RepairInterval{{Start: "0", Fixed: "1.2.4"}},
		}}
	}
	for _, tc := range []struct {
		name, displayedVersion, score, pkg, version, wantUpgrade string
		wantCoverage                                             int
	}{
		{"matching evidence", "1.2.3", "8.0", "example", installed, "v1.2.4", 2},
		{"different displayed version", "v1.2.5", "8.0", "example", installed, "", 0},
		{"different target package", installed, "8.0", "other", installed, "", 0},
		{"different target version", installed, "8.0", "example", "v1.2.2", "", 0},
		{"different secondary package", installed, "6.0", "other", installed, "v1.2.4", 1},
		{"different secondary version", installed, "6.0", "example", "v1.2.2", "v1.2.4", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bom := FormattedSBOM{ComponentInfo: map[string]Component{
				"example": {Name: "example", Version: tc.displayedVersion, Vulns: []Vuln{
					newFinding("TEST-1", "9.0", "example", installed),
					newFinding("TEST-2", tc.score, tc.pkg, tc.version),
				}},
			}}
			got := bom.RemediationAssessments(nil)
			require.Len(t, got, 1)
			require.Equal(t, tc.wantUpgrade, got[0].Upgrade)
			require.Equal(t, tc.wantCoverage, got[0].Covered)
		})
	}
}
