//go:build unit

package ssbom

import (
	"slices"
	"testing"

	"ex-sbom/client/first"
	"github.com/stretchr/testify/require"
)

func confirmedVersion(ecosystem, name, version string) *InstalledVersionEvidence {
	return &InstalledVersionEvidence{Ecosystem: ecosystem, Package: name, Version: version, Confirmed: true}
}

func TestRemediationPolicyAtDefaultThresholds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		finding  Vuln
		archive  string
		priority RemediationPriority
	}{
		{"both inclusive", Vuln{CVSSScore: "7.0", EPSS: "0.10"}, LEVArchiveDisabled, RemediationElevated},
		{"rounded display only", Vuln{CVSSScore: "7.0", EPSS: "0.09999"}, LEVArchiveDisabled, RemediationAttention},
		{"CVSS only", Vuln{CVSSScore: "9.8"}, LEVArchiveDisabled, RemediationAttention},
		{"EPSS only", Vuln{EPSS: "0.95"}, LEVArchiveDisabled, RemediationAttention},
		{"valid zero", Vuln{CVSSScore: "0", EPSS: "0", KEV: KEVUnlisted}, LEVArchiveDisabled, RemediationRoutine},
		{"unknown severity", Vuln{EPSS: "0", KEV: KEVUnlisted}, LEVArchiveDisabled, RemediationReview},
		{"KEV check missing", Vuln{CVSSScore: "0", EPSS: "0"}, LEVArchiveDisabled, RemediationReview},
		{"LEV status missing", Vuln{CVSSScore: "0", EPSS: "0", KEV: KEVUnlisted}, "", RemediationReview},
		{"lower bound below threshold", Vuln{CVSSScore: "3.1", EPSS: "0.02", KEV: KEVUnlisted, LEV: "0.06", LEVMethod: first.LEVMethod, LEVPartial: true}, LEVArchiveConfigured, RemediationReview},
		{"lower bound reaches threshold", Vuln{CVSSScore: "3.1", EPSS: "0.02", KEV: KEVUnlisted, LEV: "0.10", LEVMethod: first.LEVMethod, LEVPartial: true}, LEVArchiveConfigured, RemediationAttention},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &ReportSource{LEVArchiveStatus: tc.archive}
			got := assessFinding(tc.finding, "1.0.0", new(RemediationThreshold), source)
			require.Equal(t, tc.priority, got.Priority)
			withoutPolicy := assessFinding(tc.finding, "1.0.0", nil, source)
			require.Equal(t, RemediationReview, withoutPolicy.Priority)
		})
	}
}

func TestRemediationDoesNotCombineThresholdsAcrossFindings(t *testing.T) {
	findings := []Vuln{
		{ID: "severity-only", CVSSScore: "9.8"},
		{ID: "likelihood-only", EPSS: "0.2"},
	}
	bom := FormattedSBOM{
		ReportSource: &ReportSource{LEVArchiveStatus: LEVArchiveDisabled},
		ComponentInfo: map[string]Component{
			"split":   {Vulns: findings},
			"routine": {Vulns: []Vuln{{CVSSScore: "1", EPSS: "0", KEV: KEVUnlisted}}},
			"review":  {Vulns: []Vuln{{CVSSScore: "1"}}},
		},
	}
	for range 2 {
		got := bom.RemediationAssessments(new(RemediationThreshold))
		require.Len(t, got, 3)
		require.Equal(t, "split", got[0].Key)
		require.Equal(t, RemediationAttention, got[0].Driver.Priority)
		require.Equal(t, "likelihood-only", got[0].Driver.Finding.ID)
		require.Equal(t, "review", got[1].Key)
		require.Equal(t, "routine", got[2].Key)
		slices.Reverse(findings)
	}
}

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

func TestRemediationDriverBreaksTieByLastAffectedVersion(t *testing.T) {
	first := Vuln{ID: "CVE-2025-0001", CVSSScore: "8.0", EPSS: "0.5", RepairEvidence: &RepairEvidence{
		AdvisoryID: "CVE-2025-0001", Ecosystem: "npm", Package: "fixture", Installed: "1.0.0",
		Ranges: []RepairInterval{{Start: "0", Last: "1.1.0"}},
	}}
	second := first
	evidence := *first.RepairEvidence
	evidence.Ranges = []RepairInterval{{Start: "0", Last: "1.2.0"}}
	second.RepairEvidence = &evidence
	findings := []Vuln{first, second}
	bom := FormattedSBOM{ComponentInfo: map[string]Component{
		"fixture": {Name: "fixture", Version: "1.0.0", Vulns: findings},
	}}
	for range 2 {
		got := bom.RemediationAssessments(new(RemediationThreshold))
		require.Len(t, got, 1)
		require.Equal(t, first, got[0].Driver.Finding)
		slices.Reverse(findings)
	}
}

func TestRemediationAssessments(t *testing.T) {
	urgent := Vuln{ID: "GHSA-test", KEV: KEVListed, KEVCVE: "CVE-2024-0001", CVEIDs: []string{"CVE-2024-0001"}}
	unversionedKEV := urgent
	unversionedKEV.RepairEvidence = &RepairEvidence{
		AdvisoryID: urgent.ID, Ecosystem: "npm", Package: "fixture", Installed: "1.0.0",
		Ranges: []RepairInterval{{Start: "0", Fixed: "1.2.3"}},
	}
	bom := FormattedSBOM{ComponentInfo: map[string]Component{
		"a-unknown-version": {Name: "unknown version", Vulns: []Vuln{unversionedKEV}},
		"b-urgent":          {Name: "urgent", Version: "1", InstalledVersion: confirmedVersion("npm", "urgent", "1"), Vulns: []Vuln{urgent, urgent}},
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
	require.Equal(t, "a-unknown-version", got[1].Key)
	require.Equal(t, RemediationElevated, got[1].Driver.Priority)
	require.True(t, got[1].Driver.KEVMatch)
	require.Empty(t, got[1].Upgrade)
	require.Equal(t, "d-exact", got[2].Key)
	require.Equal(t, "c-mixed", got[3].Key)
	require.Equal(t, "higher-signal", got[3].Driver.Finding.ID)
	require.Equal(t, 5.0, got[3].Driver.CVSS)
	require.Equal(t, 0, got[3].NeedsReview)
	require.Equal(t, RemediationAttention, got[3].Driver.Priority)
	require.Equal(t, RemediationReview, bom.RemediationAssessments(nil)[2].Driver.Priority)
}

func TestRemediationThresholdUsesUnroundedValue(t *testing.T) {
	threshold := 0.8
	finding := Vuln{CVSSScore: "8", EPSS: "0.799999"}
	require.Equal(t, RemediationAttention, assessFinding(finding, "1", &threshold, nil).Priority)
	finding.EPSS = "0.8"
	require.Equal(t, RemediationElevated, assessFinding(finding, "1", &threshold, nil).Priority)
}

func TestRemediationPreservesAllKEVMatches(t *testing.T) {
	ids := []string{"CVE-2024-0001", "CVE-2024-0002"}
	finding := Vuln{CVEIDs: ids, KEV: KEVListed, KEVCVEs: ids}
	bom := FormattedSBOM{ComponentInfo: map[string]Component{
		"dependency": {Name: "dependency", Version: "1", InstalledVersion: confirmedVersion("npm", "dependency", "1"), Vulns: []Vuln{finding}},
	}}
	entry := bom.RemediationAssessments(nil)[0]
	require.Equal(t, ids, entry.UrgentCVEs)
	require.Equal(t, ids, entry.ResidualUrgentCVEs)
}

func TestRemediationPolicyEvidenceOrder(t *testing.T) {
	source := &ReportSource{LEVArchiveStatus: LEVArchiveDisabled}
	bom := FormattedSBOM{ReportSource: source, ComponentInfo: map[string]Component{}}
	cases := []struct {
		key      string
		finding  Vuln
		priority RemediationPriority
	}{
		{"high-unscored-epss", Vuln{EPSS: "0.95"}, RemediationAttention},
		{"low-scored-at-epss-threshold", Vuln{CVSSScore: "2.0", EPSS: "0.10"}, RemediationAttention},
		{"high-cvss-default-archive", Vuln{CVSSScore: "9.8", EPSS: "0.0458", KEV: KEVUnlisted}, RemediationAttention},
		{"exact-high-cvss-without-signals", Vuln{CVSSScore: "7.0"}, RemediationAttention},
		{"higher-cvss-needing-review", Vuln{CVSSScore: "6.9"}, RemediationReview},
		{"lower-cvss-needing-review", Vuln{CVSSScore: "3.1", EPSS: "0.09"}, RemediationReview},
		{"routine-both-enabled-signals-complete", Vuln{CVSSScore: "3.1", EPSS: "0.002", KEV: KEVUnlisted}, RemediationRoutine},
	}
	for _, tc := range cases {
		bom.ComponentInfo[tc.key] = Component{Name: tc.key, Version: "1", Vulns: []Vuln{tc.finding}}
	}
	got := bom.RemediationAssessments(new(RemediationThreshold))
	require.Len(t, got, len(cases))
	for i, tc := range cases {
		require.Equal(t, tc.key, got[i].Key)
		require.Equal(t, tc.priority, got[i].Driver.Priority, tc.key)
	}
	require.True(t, got[len(got)-1].Driver.Signal.Complete)
}

func TestRemediationWithConfiguredOrUnknownArchive(t *testing.T) {
	bom := FormattedSBOM{
		ReportSource: &ReportSource{LEVArchiveStatus: LEVArchiveConfigured},
		ComponentInfo: map[string]Component{
			"unscored-high-lev": {Version: "1", Vulns: []Vuln{{LEV: "0.55", LEVMethod: first.LEVMethod, LEVPartial: true}}},
			"high-cvss-partial": {Version: "1", Vulns: []Vuln{{CVSSScore: "9.8", EPSS: "0.02", LEV: "0.06", LEVMethod: first.LEVMethod, LEVPartial: true, KEV: KEVUnlisted}}},
			"missing-lev":       {Version: "1", Vulns: []Vuln{{CVSSScore: "3.1", EPSS: "0.02", KEV: KEVUnlisted}}},
			"complete-lev":      {Version: "1", Vulns: []Vuln{{CVSSScore: "3.1", EPSS: "0.02", LEV: "0.002", LEVMethod: first.LEVMethod, KEV: KEVUnlisted}}},
		},
	}
	got := bom.RemediationAssessments(new(RemediationThreshold))
	require.Len(t, got, 4)
	require.Equal(t, "unscored-high-lev", got[0].Key)
	require.Equal(t, RemediationAttention, got[0].Driver.Priority)
	require.Equal(t, "high-cvss-partial", got[1].Key)
	require.Equal(t, RemediationAttention, got[1].Driver.Priority)
	require.Equal(t, "missing-lev", got[2].Key)
	require.Equal(t, RemediationReview, got[2].Driver.Priority)
	require.False(t, got[2].Driver.Signal.Complete)
	require.Equal(t, "complete-lev", got[3].Key)
	require.Equal(t, RemediationRoutine, got[3].Driver.Priority)
	bom.ReportSource = nil
	require.Equal(t, RemediationReview, bom.RemediationAssessments(new(RemediationThreshold))[2].Driver.Priority)
}

func TestRemediationUsesSignalEvidenceToBreakPriorityTies(t *testing.T) {
	bom := FormattedSBOM{ComponentInfo: map[string]Component{
		"a-missing": {Version: "1", Vulns: []Vuln{{CVSSScore: "9.8"}}},
		"b-partial": {Version: "1", Vulns: []Vuln{{CVSSScore: "9.8", EPSS: "0"}}},
		"c-complete": {Version: "1", Vulns: []Vuln{{
			CVSSScore: "9.8", EPSS: "0", LEV: "0", LEVMethod: first.LEVMethod, KEV: KEVUnlisted,
		}}},
	}}
	got := bom.RemediationAssessments(new(RemediationThreshold))
	require.Equal(t, []string{"c-complete", "b-partial", "a-missing"}, []string{got[0].Key, got[1].Key, got[2].Key})
}

func TestRemediationKeepsTheReviewSampleInEvidenceOrder(t *testing.T) {
	bom := FormattedSBOM{
		ReportSource: &ReportSource{LEVArchiveStatus: LEVArchiveDisabled},
		ComponentInfo: map[string]Component{
			"minimist": {Name: "minimist", Version: "1.2.5", Vulns: []Vuln{
				{ID: "CVE-2021-44906", CVSSScore: "9.8", EPSS: "0.04581", EPSSDate: "2026-11-22", KEV: KEVUnlisted},
			}},
			"lodash": {Name: "lodash", Version: "4.17.20", Vulns: []Vuln{
				{ID: "CVE-2026-4800", CVSSScore: "8.1", EPSS: "0.0287", EPSSDate: "2026-11-22", KEV: KEVUnlisted},
				{ID: "CVE-2021-23337", CVSSScore: "7.2", EPSS: "0.20158", EPSSDate: "2026-11-22", KEV: KEVUnlisted},
			}},
		},
	}
	got := bom.RemediationAssessments(new(RemediationThreshold))
	require.Len(t, got, 2)
	require.Equal(t, "lodash", got[0].Name)
	require.Equal(t, "CVE-2021-23337", got[0].Driver.Finding.ID)
	require.Equal(t, RemediationElevated, got[0].Driver.Priority)
	require.Equal(t, "minimist", got[1].Name)
	require.Equal(t, "CVE-2021-44906", got[1].Driver.Finding.ID)
	require.Equal(t, RemediationAttention, got[1].Driver.Priority)
}

func TestRemediationBreaksTiesByKEVAndThenCVSS(t *testing.T) {
	const cve = "CVE-2025-1234"
	for _, tc := range []struct {
		name   string
		first  Vuln
		second Vuln
	}{
		{
			name:   "KEV with unconfirmed installed version",
			first:  Vuln{ID: cve, CVEIDs: []string{cve}, CVSSScore: "8", KEV: KEVListed, KEVCVE: cve},
			second: Vuln{CVSSScore: "8", EPSS: "1"},
		},
		{
			name:   "higher CVSS with the same exploitation signal",
			first:  Vuln{CVSSScore: "9.8", EPSS: "1"},
			second: Vuln{CVSSScore: "8", EPSS: "1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bom := FormattedSBOM{ComponentInfo: map[string]Component{
				"a-second": {Vulns: []Vuln{tc.second}},
				"z-first":  {Vulns: []Vuln{tc.first}},
			}}
			got := bom.RemediationAssessments(new(RemediationThreshold))
			require.Len(t, got, 2)
			for _, entry := range got {
				require.Equal(t, RemediationElevated, entry.Driver.Priority)
				require.True(t, entry.Driver.Signal.Complete)
				require.Equal(t, 1.0, entry.Driver.Signal.Value)
			}
			require.Equal(t, []string{"z-first", "a-second"}, []string{got[0].Key, got[1].Key})
		})
	}
}

func TestRemediationUsesRepairCoverageToBreakDriverTies(t *testing.T) {
	repair := &RepairEvidence{Ecosystem: "npm", Package: "fixture", Installed: "1.0.0",
		Ranges: []RepairInterval{{Start: "0", Fixed: "1.2.3"}}}
	driver := Vuln{ID: "CVE-2025-0001", CVSSScore: "9.8", EPSS: "0.2", RepairEvidence: repair}
	secondary := Vuln{ID: "CVE-2025-0002", CVSSScore: "7.0", RepairEvidence: repair}
	bom := FormattedSBOM{ComponentInfo: map[string]Component{
		"a-one": {Version: "1.0.0", Vulns: []Vuln{driver}},
		"b-two": {Version: "1.0.0", Vulns: []Vuln{driver, secondary}},
	}}
	got := bom.RemediationAssessments(new(RemediationThreshold))
	require.Equal(t, "b-two", got[0].Key)
	require.Equal(t, 2, got[0].Covered)
	require.Equal(t, "a-one", got[1].Key)
}
