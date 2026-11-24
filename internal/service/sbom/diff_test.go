// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package ssbom

import (
	"encoding/json"

	"ex-sbom/client/first"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ─── maxVulnScore ─────────────────────────────────────────────────────────────

func TestMaxVulnScore_EmptyVulns(t *testing.T) {
	// Arrange
	vulns := []Vuln{}

	// Act
	result := maxVulnScore(vulns, func(v Vuln) string { return v.CVSSScore })

	// Assert
	assert.Equal(t, "", result)
}

func TestMaxVulnScore_SingleVuln(t *testing.T) {
	// Arrange
	vulns := []Vuln{{CVSSScore: "7.5"}}

	// Act
	result := maxVulnScore(vulns, func(v Vuln) string { return v.CVSSScore })

	// Assert
	assert.Equal(t, "7.5", result)
}

func TestMaxVulnScore_ReturnsHighest(t *testing.T) {
	// Arrange
	vulns := []Vuln{
		{CVSSScore: "5.0"},
		{CVSSScore: "9.8"},
		{CVSSScore: "7.2"},
	}

	// Act
	result := maxVulnScore(vulns, func(v Vuln) string { return v.CVSSScore })

	// Assert
	assert.Equal(t, "9.8", result)
}

func TestMaxVulnScore_SkipsEmptyAndInvalidScores(t *testing.T) {
	// Arrange
	vulns := []Vuln{
		{CVSSScore: ""},
		{CVSSScore: "not-a-number"},
		{CVSSScore: "6.1"},
	}

	// Act
	result := maxVulnScore(vulns, func(v Vuln) string { return v.CVSSScore })

	// Assert
	assert.Equal(t, "6.1", result)
}

func TestMaxVulnScore_PreservesZero(t *testing.T) {
	vulns := []Vuln{{EPSS: "NaN"}, {EPSS: "0"}, {EPSS: "+Inf"}}
	assert.Equal(t, "0", maxVulnScore(vulns, func(v Vuln) string { return v.EPSS }))
}

func TestMaxVulnScore_AllInvalid(t *testing.T) {
	// Arrange
	vulns := []Vuln{
		{CVSSScore: "N/A"},
		{CVSSScore: ""},
	}

	// Act
	result := maxVulnScore(vulns, func(v Vuln) string { return v.CVSSScore })

	// Assert
	assert.Equal(t, "", result)
}

// ─── DiffSBOMs ───────────────────────────────────────────────────────────────

func makeSBOM(components map[string]Component, levels map[string]int) FormattedSBOM {
	return FormattedSBOM{
		ComponentInfo:    components,
		ComponentToLevel: levels,
	}
}

func TestDiffSBOMs_IdenticalSBOMs(t *testing.T) {
	// Arrange
	comp := Component{Version: "1.0.0", VulnNumber: 0}
	sbomA := makeSBOM(map[string]Component{"curl": comp}, map[string]int{"curl": 1})
	sbomB := makeSBOM(map[string]Component{"curl": comp}, map[string]int{"curl": 1})

	// Act
	result := DiffSBOMs(sbomA, sbomB)

	// Assert
	assert.Empty(t, result.ByLevel, "identical SBOMs should produce no diff")
}

func TestDiffSBOMs_SameCountRiskChanges(t *testing.T) {
	base := Component{
		Version: "1.0.0", VulnNumber: 2,
		Vulns: []Vuln{
			{ID: "CVE-2025-0001", CVEIDs: []string{"CVE-2025-0001"}, CVSSScore: "7.1", EPSS: "0.1", LEV: "0.2", LEVMethod: first.LEVMethod, KEV: KEVUnlisted},
			{ID: "CVE-2", CVSSScore: "4.0", EPSS: "0.3", LEV: "0.4"},
		},
	}
	tests := []struct {
		name    string
		change  func(*Component)
		changed bool
	}{
		{"reordered findings", func(c *Component) { c.Vulns[0], c.Vulns[1] = c.Vulns[1], c.Vulns[0] }, false},
		{"replaced identity", func(c *Component) { c.Vulns[0].ID = "CVE-3" }, true},
		{"changed CVSS", func(c *Component) { c.Vulns[0].CVSSScore = "7.2" }, true},
		{"changed EPSS", func(c *Component) { c.Vulns[0].EPSS = "0.2" }, true},
		{"changed LEV", func(c *Component) { c.Vulns[0].LEV = "0.3" }, true},
		{"changed LEV certainty", func(c *Component) { c.Vulns[0].LEVPartial = true }, true},
		{"listed in KEV", func(c *Component) {
			c.Vulns[0].KEV = KEVListed
			c.Vulns[0].KEVCVEs = c.Vulns[0].CVEIDs
		}, true},
		{"changed unverified LEV", func(c *Component) { c.Vulns[1].LEV = "0.9" }, false},
		{"changed unverified LEV certainty", func(c *Component) { c.Vulns[1].LEVPartial = true }, false},
		{"changed dependency risk", func(c *Component) { c.ContainsVulnDep = true }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newComponent := base
			newComponent.Vulns = append([]Vuln(nil), base.Vulns...)
			tt.change(&newComponent)
			a := makeSBOM(map[string]Component{"pkg": base}, map[string]int{"pkg": 0})
			b := makeSBOM(map[string]Component{"pkg": newComponent}, map[string]int{"pkg": 0})
			result := DiffSBOMs(a, b)
			if tt.changed && assert.Contains(t, result.ByLevel, 0) {
				assert.Len(t, result.ByLevel[0].Changed, 1)
			} else if !tt.changed {
				assert.Empty(t, result.ByLevel)
			}
		})
	}
}

func TestDiffSBOMs_EmptyEPSScoreBecomesPartial(t *testing.T) {
	before := Component{Version: "1.0.0", VulnNumber: 2, Vulns: []Vuln{
		{ID: "TEST-SCORED", EPSS: "0.2"},
		{ID: "TEST-MISSING"},
	}}
	after := before
	after.Vulns = append([]Vuln(nil), before.Vulns...)
	after.Vulns[1].EPSSPartial = true

	a := makeSBOM(map[string]Component{"pkg": before}, map[string]int{"pkg": 0})
	b := makeSBOM(map[string]Component{"pkg": after}, map[string]int{"pkg": 0})
	result := DiffSBOMs(a, b)
	if assert.Contains(t, result.ByLevel, 0) {
		changes := result.ByLevel[0].Changed
		if assert.Len(t, changes, 1) {
			assert.Equal(t, "0.2", changes[0].MaxEpssA)
			assert.Empty(t, changes[0].MaxEpssB)
		}
	}
}

func TestDiffSBOMs_AddedComponent(t *testing.T) {
	// Arrange
	sbomA := makeSBOM(map[string]Component{}, map[string]int{})
	sbomB := makeSBOM(
		map[string]Component{"zlib": {Version: "1.2.11"}},
		map[string]int{"zlib": 2},
	)

	// Act
	result := DiffSBOMs(sbomA, sbomB)

	// Assert
	level2, ok := result.ByLevel[2]
	assert.True(t, ok)
	assert.Len(t, level2.Added, 1)
	assert.Equal(t, "zlib", level2.Added[0].Name)
	assert.Equal(t, "1.2.11", level2.Added[0].VersionB)
	assert.Empty(t, level2.Removed)
	assert.Empty(t, level2.Changed)
}

func TestDiffSBOMs_RemovedComponent(t *testing.T) {
	// Arrange
	sbomA := makeSBOM(
		map[string]Component{"openssl": {Version: "3.0.0"}},
		map[string]int{"openssl": 1},
	)
	sbomB := makeSBOM(map[string]Component{}, map[string]int{})

	// Act
	result := DiffSBOMs(sbomA, sbomB)

	// Assert
	level1, ok := result.ByLevel[1]
	assert.True(t, ok)
	assert.Len(t, level1.Removed, 1)
	assert.Equal(t, "openssl", level1.Removed[0].Name)
	assert.Equal(t, "3.0.0", level1.Removed[0].VersionA)
	assert.Empty(t, level1.Added)
	assert.Empty(t, level1.Changed)
}

func TestDiffSBOMs_ChangedVersion(t *testing.T) {
	// Arrange
	sbomA := makeSBOM(
		map[string]Component{"nginx": {Version: "1.24.0", VulnNumber: 0}},
		map[string]int{"nginx": 0},
	)
	sbomB := makeSBOM(
		map[string]Component{"nginx": {Version: "1.25.0", VulnNumber: 0}},
		map[string]int{"nginx": 0},
	)

	// Act
	result := DiffSBOMs(sbomA, sbomB)

	// Assert
	level0, ok := result.ByLevel[0]
	assert.True(t, ok)
	assert.Len(t, level0.Changed, 1)
	assert.Equal(t, "nginx", level0.Changed[0].Name)
	assert.Equal(t, "1.24.0", level0.Changed[0].VersionA)
	assert.Equal(t, "1.25.0", level0.Changed[0].VersionB)
}

func TestDiffSBOMs_ChangedComponentUsesEachSnapshotKey(t *testing.T) {
	a := makeSBOM(map[string]Component{
		"fixture": {Name: "fixture", Version: "1.0"},
	}, map[string]int{"fixture": 1})
	b := makeSBOM(map[string]Component{
		"fixture (first)":  {Name: "fixture", Version: "1.0"},
		"fixture (second)": {Name: "fixture", Version: "2.0"},
	}, map[string]int{"fixture (first)": 2, "fixture (second)": 3})

	result := DiffSBOMs(a, b)
	if assert.Len(t, result.ByLevel[1].Changed, 1) {
		changed := result.ByLevel[1].Changed[0]
		assert.Equal(t, "fixture", changed.Name)
		assert.Equal(t, "fixture (first)", changed.KeyB)
		assert.Equal(t, 2, *changed.LevelB)
	}
	assert.Equal(t, "fixture (second)", result.ByLevel[3].Added[0].Name)
}

func TestDiffSBOMs_DoesNotGuessAmbiguousSameNameUpgrades(t *testing.T) {
	a := makeSBOM(map[string]Component{
		"fixture (first)":  {Name: "fixture", Version: "1.0"},
		"fixture (second)": {Name: "fixture", Version: "2.0"},
	}, nil)
	b := makeSBOM(map[string]Component{
		"fixture": {Name: "fixture", Version: "3.0"},
	}, nil)

	result := DiffSBOMs(a, b)
	assert.Len(t, result.ByLevel[0].Removed, 2)
	assert.Len(t, result.ByLevel[0].Added, 1)
	assert.Empty(t, result.ByLevel[0].Changed)
}

func TestDiffSBOMs_MultipleSameNameUpgradesWithStableAliases(t *testing.T) {
	a := makeSBOM(map[string]Component{
		"fixture (first)":  {Name: "fixture", Version: "1.0"},
		"fixture (second)": {Name: "fixture", Version: "2.0"},
	}, nil)
	tests := []struct {
		name   string
		first  string
		second string
	}{
		{name: "distinct versions", first: "1.1", second: "2.1"},
		{name: "overlapping versions", first: "2.0", second: "3.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := makeSBOM(map[string]Component{
				"fixture (first)":  {Name: "fixture", Version: tt.first},
				"fixture (second)": {Name: "fixture", Version: tt.second},
			}, nil)

			level := DiffSBOMs(a, b).ByLevel[0]
			assert.Empty(t, level.Added)
			assert.Empty(t, level.Removed)
			assert.ElementsMatch(t, []ComponentDiff{
				{Name: "fixture (first)", VersionA: "1.0", VersionB: tt.first, LevelA: new(int), LevelB: new(int)},
				{Name: "fixture (second)", VersionA: "2.0", VersionB: tt.second, LevelA: new(int), LevelB: new(int)},
			}, level.Changed)
		})
	}
}

func TestDiffSBOMs_ChangedVulnCount(t *testing.T) {
	// Arrange
	sbomA := makeSBOM(
		map[string]Component{"curl": {Version: "7.88.0", VulnNumber: 0}},
		map[string]int{"curl": 1},
	)
	sbomB := makeSBOM(
		map[string]Component{"curl": {Version: "7.88.0", VulnNumber: 3}},
		map[string]int{"curl": 1},
	)

	// Act
	result := DiffSBOMs(sbomA, sbomB)

	// Assert
	level1, ok := result.ByLevel[1]
	assert.True(t, ok)
	assert.Len(t, level1.Changed, 1)
	assert.Equal(t, 0, level1.Changed[0].VulnsA)
	assert.Equal(t, 3, level1.Changed[0].VulnsB)
}

func TestDiffSBOMs_UnchangedComponentNotInResult(t *testing.T) {
	// Arrange: two components, one changed, one identical
	sbomA := makeSBOM(
		map[string]Component{
			"curl":    {Version: "7.88.0", VulnNumber: 0},
			"openssl": {Version: "3.0.0", VulnNumber: 1},
		},
		map[string]int{"curl": 1, "openssl": 1},
	)
	sbomB := makeSBOM(
		map[string]Component{
			"curl":    {Version: "7.89.0", VulnNumber: 0}, // changed
			"openssl": {Version: "3.0.0", VulnNumber: 1},  // same
		},
		map[string]int{"curl": 1, "openssl": 1},
	)

	// Act
	result := DiffSBOMs(sbomA, sbomB)

	// Assert
	level1, ok := result.ByLevel[1]
	assert.True(t, ok)
	assert.Len(t, level1.Changed, 1)
	assert.Equal(t, "curl", level1.Changed[0].Name)
}

func TestDiffSBOMs_VulnTotalsPerLevel(t *testing.T) {
	// Arrange: one removed (3 vulns), one added (2 vulns), one changed (1→4 vulns)
	sbomA := makeSBOM(
		map[string]Component{
			"removed": {Version: "1.0.0", VulnNumber: 3},
			"changed": {Version: "1.0.0", VulnNumber: 1},
		},
		map[string]int{"removed": 0, "changed": 0},
	)
	sbomB := makeSBOM(
		map[string]Component{
			"added":   {Version: "1.0.0", VulnNumber: 2},
			"changed": {Version: "2.0.0", VulnNumber: 4},
		},
		map[string]int{"added": 0, "changed": 0},
	)

	// Act
	result := DiffSBOMs(sbomA, sbomB)

	// Assert
	level0 := result.ByLevel[0]
	assert.NotNil(t, level0)
	// TotalVulnsA = removed(3) + changed(1) = 4
	assert.Equal(t, 4, level0.TotalVulnsA)
	// TotalVulnsB = added(2) + changed(4) = 6
	assert.Equal(t, 6, level0.TotalVulnsB)
}

func TestDiffSBOMs_VulnTotalsIncludeUnchangedAndMovedComponents(t *testing.T) {
	unchanged := Component{VulnNumber: 5}
	a := makeSBOM(
		map[string]Component{"unchanged": unchanged, "moved": {VulnNumber: 1}},
		map[string]int{"unchanged": 0, "moved": 0},
	)
	b := makeSBOM(
		map[string]Component{"unchanged": unchanged, "moved": {VulnNumber: 2}},
		map[string]int{"unchanged": 0, "moved": 1},
	)

	result := DiffSBOMs(a, b)
	assert.Equal(t, 6, result.ByLevel[0].TotalVulnsA)
	assert.Equal(t, 5, result.ByLevel[0].TotalVulnsB)
	assert.Len(t, result.ByLevel[0].Changed, 1)
	assert.Equal(t, 0, result.ByLevel[1].TotalVulnsA)
	assert.Equal(t, 2, result.ByLevel[1].TotalVulnsB)
	assert.Empty(t, result.ByLevel[1].Changed)
}

func TestDiffSBOMs_HasVulnFlagOnChanged(t *testing.T) {
	// Arrange: version changes, one side has vulns
	sbomA := makeSBOM(
		map[string]Component{"pkg": {Version: "1.0.0", VulnNumber: 0}},
		map[string]int{"pkg": 1},
	)
	sbomB := makeSBOM(
		map[string]Component{"pkg": {Version: "2.0.0", VulnNumber: 2}},
		map[string]int{"pkg": 1},
	)

	// Act
	result := DiffSBOMs(sbomA, sbomB)

	// Assert
	diff := result.ByLevel[1].Changed[0]
	assert.True(t, diff.HasVuln, "HasVuln should be true when either side has vulns")
}

func TestDiffSBOMs_ChangedDependencyLevelOnly(t *testing.T) {
	// Arrange: same version and vuln count, only the dependency level moves.
	comp := Component{Version: "1.0.0", VulnNumber: 2}
	sbomA := makeSBOM(map[string]Component{"libfoo": comp}, map[string]int{"libfoo": 2})
	sbomB := makeSBOM(map[string]Component{"libfoo": comp}, map[string]int{"libfoo": 3})

	// Act
	result := DiffSBOMs(sbomA, sbomB)

	// Assert: reported as changed under level A, with both levels populated.
	level2, ok := result.ByLevel[2]
	assert.True(t, ok, "level-only change must be reported")
	assert.Len(t, level2.Changed, 1)

	changed := level2.Changed[0]
	assert.Equal(t, "libfoo", changed.Name)
	assert.Equal(t, changed.VersionA, changed.VersionB, "version did not change")
	assert.Equal(t, changed.VulnsA, changed.VulnsB, "vuln count did not change")
	assert.NotNil(t, changed.LevelA)
	assert.NotNil(t, changed.LevelB)
	assert.Equal(t, 2, *changed.LevelA)
	assert.Equal(t, 3, *changed.LevelB)
}

func TestDiffSBOMs_ChangedLevelToZeroIsPreserved(t *testing.T) {
	// Arrange: component moves from level 1 to level 0 (root).
	comp := Component{Version: "1.0.0"}
	sbomA := makeSBOM(map[string]Component{"libbar": comp}, map[string]int{"libbar": 1})
	sbomB := makeSBOM(map[string]Component{"libbar": comp}, map[string]int{"libbar": 0})

	// Act
	result := DiffSBOMs(sbomA, sbomB)

	// Assert: level 0 must survive both in the struct and in JSON output.
	level1, ok := result.ByLevel[1]
	assert.True(t, ok)
	assert.Len(t, level1.Changed, 1)

	changed := level1.Changed[0]
	assert.NotNil(t, changed.LevelB)
	assert.Equal(t, 0, *changed.LevelB)

	data, err := json.Marshal(changed)
	assert.NoError(t, err)
	assert.Contains(t, string(data), `"level_a":1`)
	assert.Contains(t, string(data), `"level_b":0`, "level 0 must not be dropped by omitempty")
}

func TestRiskFieldsProbabilityMaxima(t *testing.T) {
	cases := []struct {
		name     string
		findings []Vuln
		wantEPSS string
		wantLEV  string
	}{
		{
			name: "partial EPSS above the complete score",
			findings: []Vuln{
				{EPSS: "0.2", LEV: "0.3", LEVMethod: first.LEVMethod},
				{EPSS: "0.8", EPSSPartial: true},
			},
			wantLEV: "0.3",
		},
		{
			name: "partial verified LEV above the complete score",
			findings: []Vuln{
				{EPSS: "0.2", LEV: "0.3", LEVMethod: first.LEVMethod},
				{LEV: "0.8", LEVMethod: first.LEVMethod, LEVPartial: true},
			},
			wantEPSS: "0.2",
		},
		{
			name: "explicitly missing EPSS alongside a complete score",
			findings: []Vuln{
				{EPSS: "0.2"},
				{EPSSPartial: true},
			},
		},
		{
			name: "unknown legacy LEV and valid zero",
			findings: []Vuln{
				{LEV: "1", LEVPartial: true},
				{EPSS: "0", LEV: "0", LEVMethod: first.LEVMethod},
			},
			wantEPSS: "0",
			wantLEV:  "0",
		},
		{
			name: "complete findings use the highest verified scores",
			findings: []Vuln{
				{EPSS: "0.4", LEV: "1", LEVMethod: first.LEVMethod},
				{EPSS: "0.8", LEV: "0.8", LEVMethod: first.LEVMethod},
			},
			wantEPSS: "0.8",
			wantLEV:  "1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, epss, lev, _ := riskFields(Component{Vulns: tc.findings})
			assert.Equal(t, tc.wantEPSS, epss)
			assert.Equal(t, tc.wantLEV, lev)
		})
	}
}
