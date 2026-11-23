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
	component := Component{Name: "body-parser", Version: "1.19.0", Vulns: []Vuln{early, late, urgent}}
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
