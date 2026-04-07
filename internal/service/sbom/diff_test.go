// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package ssbom

import (
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
