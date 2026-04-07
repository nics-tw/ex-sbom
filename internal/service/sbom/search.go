// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"ex-sbom/internal/domain"
	"strings"
)

// SearchResult represents a single search hit.
type SearchResult struct {
	SBOM       domain.Version `json:"sbom"`
	Component  string         `json:"component"`
	Version    string         `json:"version"`
	VulnCount  int            `json:"vuln_count"`
	Level      int            `json:"level"`
	HasVuln    bool           `json:"has_vuln"`
	HasVulnDep bool           `json:"has_vuln_dep"`
	// MatchType is "component" when the component name matched,
	// or "vuln" when a CVE ID or summary matched.
	MatchType   string `json:"match_type"`
	VulnID      string `json:"vuln_id,omitempty"`
	VulnSummary string `json:"vuln_summary,omitempty"`
	CVSSScore   string `json:"cvss_score,omitempty"`
}

// searchInCache returns results matching query (case-insensitive) across all SBOMs in the provided workspace snapshot.
func searchInCache(workspace map[domain.Version]FormattedSBOM, query string) []SearchResult {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return nil
	}

	if len(workspace) == 0 {
		return nil
	}

	var results []SearchResult
	for sbomName, sbom := range workspace {
		for compName, comp := range sbom.ComponentInfo {
			nameLower := strings.ToLower(compName)
			level := sbom.ComponentToLevel[compName]
			hasVuln := comp.VulnNumber > 0
			hasVulnDep := comp.ContainsVulnDep

			// Component name match — report once, no per-vuln expansion
			if strings.Contains(nameLower, query) {
				results = append(results, SearchResult{
					SBOM:       sbomName,
					Component:  compName,
					Version:    comp.Version,
					VulnCount:  comp.VulnNumber,
					Level:      level,
					HasVuln:    hasVuln,
					HasVulnDep: hasVulnDep,
					MatchType:  "component",
				})
				continue
			}

			// CVE ID / summary match — one result per matching vuln
			for _, vuln := range comp.Vulns {
				if strings.Contains(strings.ToLower(vuln.ID), query) ||
					strings.Contains(strings.ToLower(vuln.Summary), query) {
					results = append(results, SearchResult{
						SBOM:        sbomName,
						Component:   compName,
						Version:     comp.Version,
						VulnCount:   comp.VulnNumber,
						Level:       level,
						HasVuln:     hasVuln,
						HasVulnDep:  hasVulnDep,
						MatchType:   "vuln",
						VulnID:      vuln.ID,
						VulnSummary: vuln.Summary,
						CVSSScore:   vuln.CVSSScore,
					})
				}
			}
		}
	}

	return results
}
