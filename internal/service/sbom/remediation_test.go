//go:build unit

package ssbom

import (
	"slices"
	"testing"

	"ex-sbom/client/first"
	"github.com/stretchr/testify/require"
)

func TestRemediationAssessmentOrderIsStableAcrossFindingOrder(t *testing.T) {
	threshold := RemediationThreshold
	tiedEPSS := Vuln{ID: "CVE-2025-0001", CVSSScore: "8.0", EPSS: "0.5"}
	tiedLEV := Vuln{ID: tiedEPSS.ID, CVSSScore: tiedEPSS.CVSSScore, LEV: "0.5", LEVMethod: first.LEVMethod}
	findings := []Vuln{tiedEPSS, tiedLEV}
	bom := FormattedSBOM{ComponentInfo: map[string]Component{
		"b": {Name: "b", Version: "1.0.0", Vulns: findings},
		"a": {Name: "a", Version: "1.0.0", Vulns: []Vuln{tiedEPSS}},
	}}
	firstOrder := bom.RemediationAssessments(&threshold)
	slices.Reverse(findings)
	secondOrder := bom.RemediationAssessments(&threshold)
	require.Equal(t, []string{"a", "b"}, []string{firstOrder[0].Key, firstOrder[1].Key})
	for i := range firstOrder {
		require.Equal(t, firstOrder[i].Key, secondOrder[i].Key)
		require.Equal(t, firstOrder[i].Driver.Signal, secondOrder[i].Driver.Signal)
		require.Equal(t, firstOrder[i].Driver.Finding, secondOrder[i].Driver.Finding)
		require.Equal(t, firstOrder[i].CumulativeCovered, secondOrder[i].CumulativeCovered)
		require.Equal(t, firstOrder[i].RemainingUrgent, secondOrder[i].RemainingUrgent)
	}
}

func TestRemediationAssessments(t *testing.T) {
	urgent := Vuln{ID: "GHSA-test", KEV: KEVListed, KEVCVE: "CVE-2024-0001", CVEIDs: []string{"CVE-2024-0001"}}
	bom := FormattedSBOM{ComponentInfo: map[string]Component{
		"a-unknown-version": {Name: "unknown version", Vulns: []Vuln{urgent}},
		"b-urgent":          {Name: "urgent", Version: "1", Vulns: []Vuln{urgent, urgent}},
		"c-mixed": {Name: "mixed", Version: "1", Vulns: []Vuln{
			{ID: "higher-cvss", CVSSScore: "9.5", EPSS: "0.1"},
			{ID: "higher-signal", CVSSScore: "5", EPSS: "0.8"},
		}},
		"d-exact": {Name: "exact", Version: "1", Vulns: []Vuln{
			{ID: "complete", CVSSScore: "8", EPSS: "0.8", LEV: "0.1", LEVMethod: first.LEVMethod, KEV: KEVUnlisted},
		}},
		"e-empty": {Name: "empty"},
	}}
	got := bom.RemediationAssessments(new(0.8))
	require.Len(t, got, 4)
	require.Equal(t, "b-urgent", got[0].Key)
	require.Equal(t, []string{"CVE-2024-0001"}, got[0].UrgentCVEs)
	require.Equal(t, "d-exact", got[1].Key)
	require.Equal(t, "c-mixed", got[2].Key)
	require.Equal(t, "higher-signal", got[2].Driver.Finding.ID)
	require.Equal(t, 5.0, got[2].Driver.CVSS)
	require.Equal(t, 1, got[2].NeedsReview)
	require.Equal(t, RemediationReview, got[3].Driver.Priority)
	require.Equal(t, RemediationReview, bom.RemediationAssessments(nil)[1].Driver.Priority)
}

func TestRemediationThresholdUsesUnroundedValue(t *testing.T) {
	threshold := 0.8
	finding := Vuln{CVSSScore: "8", EPSS: "0.799999"}
	require.Equal(t, RemediationReview, assessFinding(finding, "1", &threshold).Priority)
	finding.EPSS = "0.8"
	require.Equal(t, RemediationElevated, assessFinding(finding, "1", &threshold).Priority)
}

func TestRemediationPreservesAllKEVMatches(t *testing.T) {
	ids := []string{"CVE-2024-0001", "CVE-2024-0002"}
	finding := Vuln{CVEIDs: ids, KEV: KEVListed, KEVCVEs: ids}
	bom := FormattedSBOM{ComponentInfo: map[string]Component{
		"dependency": {Name: "dependency", Version: "1", Vulns: []Vuln{finding}},
	}}
	entry := bom.RemediationAssessments(nil)[0]
	require.Equal(t, ids, entry.UrgentCVEs)
	require.Equal(t, ids, entry.ResidualUrgentCVEs)
}
