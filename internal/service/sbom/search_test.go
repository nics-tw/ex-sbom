// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package ssbom

import (
	"testing"

	"ex-sbom/internal/domain"

	"github.com/stretchr/testify/assert"
)

// helpers ─────────────────────────────────────────────────────────────────────

func workspaceWithSBOM(filename domain.Version, sbom FormattedSBOM) map[domain.Version]FormattedSBOM {
	return map[domain.Version]FormattedSBOM{filename: sbom}
}

func sbomWithComponent(compName string, comp Component, level int) FormattedSBOM {
	return FormattedSBOM{
		ComponentInfo:    map[string]Component{compName: comp},
		ComponentToLevel: map[string]int{compName: level},
	}
}

// TestSearchInCache_EmptyQuery ─────────────────────────────────────────────────

func TestSearchInCache_EmptyQuery(t *testing.T) {
	// Arrange
	workspace := workspaceWithSBOM("sbom.json", sbomWithComponent("openssl", Component{Version: "1.0.0"}, 1))

	// Act
	results := searchInCache(workspace, "")

	// Assert
	assert.Nil(t, results)
}

func TestSearchInCache_WhitespaceOnlyQuery(t *testing.T) {
	// Arrange
	workspace := workspaceWithSBOM("sbom.json", sbomWithComponent("openssl", Component{Version: "1.0.0"}, 1))

	// Act
	results := searchInCache(workspace, "   ")

	// Assert
	assert.Nil(t, results)
}

// TestSearchInCache_EmptyWorkspace ────────────────────────────────────────────

func TestSearchInCache_EmptyWorkspace(t *testing.T) {
	// Arrange
	workspace := map[domain.Version]FormattedSBOM{}

	// Act
	results := searchInCache(workspace, "openssl")

	// Assert
	assert.Nil(t, results)
}

// TestSearchInCache_ComponentNameMatch ────────────────────────────────────────

func TestSearchInCache_ComponentNameMatch(t *testing.T) {
	// Arrange
	comp := Component{Version: "3.0.1", VulnNumber: 0}
	workspace := workspaceWithSBOM("sbom.json", sbomWithComponent("openssl", comp, 2))

	// Act
	results := searchInCache(workspace, "openssl")

	// Assert
	assert.Len(t, results, 1)
	assert.Equal(t, "openssl", results[0].Component)
	assert.Equal(t, "3.0.1", results[0].Version)
	assert.Equal(t, "component", results[0].MatchType)
	assert.Equal(t, 2, results[0].Level)
}

func TestSearchInCache_ComponentNamePartialMatch(t *testing.T) {
	// Arrange
	comp := Component{Version: "1.2.3"}
	workspace := workspaceWithSBOM("sbom.json", sbomWithComponent("libssl-dev", comp, 1))

	// Act
	results := searchInCache(workspace, "ssl")

	// Assert
	assert.Len(t, results, 1)
	assert.Equal(t, "libssl-dev", results[0].Component)
}

func TestSearchInCache_ComponentNameCaseInsensitive(t *testing.T) {
	// Arrange
	comp := Component{Version: "1.0.0"}
	workspace := workspaceWithSBOM("sbom.json", sbomWithComponent("OpenSSL", comp, 0))

	// Act
	results := searchInCache(workspace, "openssl")

	// Assert
	assert.Len(t, results, 1)
	assert.Equal(t, "OpenSSL", results[0].Component)
}

// TestSearchInCache_VulnIDMatch ───────────────────────────────────────────────

func TestSearchInCache_VulnIDMatch(t *testing.T) {
	// Arrange
	vuln := Vuln{ID: "CVE-2023-1234", Summary: "Buffer overflow", CVSSScore: "9.8"}
	comp := Component{Version: "1.0.0", VulnNumber: 1, Vulns: []Vuln{vuln}}
	workspace := workspaceWithSBOM("sbom.json", sbomWithComponent("curl", comp, 1))

	// Act
	results := searchInCache(workspace, "CVE-2023-1234")

	// Assert
	assert.Len(t, results, 1)
	assert.Equal(t, "vuln", results[0].MatchType)
	assert.Equal(t, "CVE-2023-1234", results[0].VulnID)
	assert.Equal(t, "Buffer overflow", results[0].VulnSummary)
	assert.Equal(t, "9.8", results[0].CVSSScore)
}

func TestSearchInCache_VulnSummaryMatch(t *testing.T) {
	// Arrange
	vuln := Vuln{ID: "CVE-2023-9999", Summary: "Remote code execution via crafted packet"}
	comp := Component{Version: "2.0.0", VulnNumber: 1, Vulns: []Vuln{vuln}}
	workspace := workspaceWithSBOM("sbom.json", sbomWithComponent("nginx", comp, 0))

	// Act
	results := searchInCache(workspace, "remote code execution")

	// Assert
	assert.Len(t, results, 1)
	assert.Equal(t, "vuln", results[0].MatchType)
	assert.Equal(t, "CVE-2023-9999", results[0].VulnID)
}

func TestSearchInCache_VulnIDCaseInsensitive(t *testing.T) {
	// Arrange
	vuln := Vuln{ID: "CVE-2023-1234", Summary: "overflow"}
	comp := Component{Version: "1.0.0", VulnNumber: 1, Vulns: []Vuln{vuln}}
	workspace := workspaceWithSBOM("sbom.json", sbomWithComponent("pkg", comp, 1))

	// Act
	results := searchInCache(workspace, "cve-2023-1234")

	// Assert
	assert.Len(t, results, 1)
	assert.Equal(t, "vuln", results[0].MatchType)
}

// TestSearchInCache_ComponentMatchSkipsVulnExpansion ──────────────────────────

func TestSearchInCache_ComponentMatchSkipsVulnExpansion(t *testing.T) {
	// Arrange: component name matches AND has 2 vulns — should return only 1 result (not 3)
	vulns := []Vuln{
		{ID: "CVE-2023-0001", Summary: "first"},
		{ID: "CVE-2023-0002", Summary: "second"},
	}
	comp := Component{Version: "1.0.0", VulnNumber: 2, Vulns: vulns}
	workspace := workspaceWithSBOM("sbom.json", sbomWithComponent("openssl", comp, 1))

	// Act
	results := searchInCache(workspace, "openssl")

	// Assert
	assert.Len(t, results, 1, "component match should not expand into per-vuln results")
	assert.Equal(t, "component", results[0].MatchType)
}

// TestSearchInCache_MultipleVulnsMatch ────────────────────────────────────────

func TestSearchInCache_MultipleVulnsMatch(t *testing.T) {
	// Arrange: two vulns both match the query — expect two results
	vulns := []Vuln{
		{ID: "CVE-2023-0001", Summary: "heap overflow in parser"},
		{ID: "CVE-2023-0002", Summary: "stack overflow in decoder"},
	}
	comp := Component{Version: "1.0.0", VulnNumber: 2, Vulns: vulns}
	workspace := workspaceWithSBOM("sbom.json", sbomWithComponent("zlib", comp, 1))

	// Act
	results := searchInCache(workspace, "overflow")

	// Assert
	assert.Len(t, results, 2)
	for _, r := range results {
		assert.Equal(t, "vuln", r.MatchType)
		assert.Equal(t, "zlib", r.Component)
	}
}

// TestSearchInCache_NoMatch ───────────────────────────────────────────────────

func TestSearchInCache_NoMatch(t *testing.T) {
	// Arrange
	comp := Component{Version: "1.0.0", Vulns: []Vuln{{ID: "CVE-2023-0001", Summary: "overflow"}}}
	workspace := workspaceWithSBOM("sbom.json", sbomWithComponent("curl", comp, 1))

	// Act
	results := searchInCache(workspace, "unrelated-query-xyz")

	// Assert
	assert.Empty(t, results)
}

// TestSearchInCache_HasVulnFields ─────────────────────────────────────────────

func TestSearchInCache_HasVulnFields(t *testing.T) {
	// Arrange
	comp := Component{
		Version:         "1.0.0",
		VulnNumber:      2,
		ContainsVulnDep: true,
	}
	workspace := workspaceWithSBOM("sbom.json", sbomWithComponent("openssl", comp, 1))

	// Act
	results := searchInCache(workspace, "openssl")

	// Assert
	assert.Len(t, results, 1)
	assert.True(t, results[0].HasVuln)
	assert.True(t, results[0].HasVulnDep)
	assert.Equal(t, 2, results[0].VulnCount)
}
