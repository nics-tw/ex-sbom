// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import "strconv"

// ComponentDiff represents a single component difference between two SBOMs.
type ComponentDiff struct {
	Name     string `json:"name"`
	VersionA string `json:"version_a,omitempty"`
	VersionB string `json:"version_b,omitempty"`
	VulnsA   int    `json:"vulns_a,omitempty"`
	VulnsB   int    `json:"vulns_b,omitempty"`
	// LevelA/LevelB are pointers so level 0 still serializes; both are set on
	// every changed entry so clients can detect topology moves.
	LevelA     *int   `json:"level_a,omitempty"`
	LevelB     *int   `json:"level_b,omitempty"`
	HasVuln    bool   `json:"has_vuln,omitempty"`
	HasVulnDep bool   `json:"has_vuln_dep,omitempty"`
	MaxCvssA   string `json:"max_cvss_a,omitempty"`
	MaxCvssB   string `json:"max_cvss_b,omitempty"`
	MaxEpssA   string `json:"max_epss_a,omitempty"`
	MaxEpssB   string `json:"max_epss_b,omitempty"`
	MaxLevA    string `json:"max_lev_a,omitempty"`
	MaxLevB    string `json:"max_lev_b,omitempty"`
	SevereA    bool   `json:"severe_a,omitempty"`
	SevereB    bool   `json:"severe_b,omitempty"`
}

// LevelDiff holds the diff for a single dependency level.
type LevelDiff struct {
	Added       []ComponentDiff `json:"added"`
	Removed     []ComponentDiff `json:"removed"`
	Changed     []ComponentDiff `json:"changed"`
	TotalVulnsA int             `json:"total_vulns_a"`
	TotalVulnsB int             `json:"total_vulns_b"`
}

// DiffResult holds the categorised diff between two SBOMs, grouped by level.
type DiffResult struct {
	ByLevel map[int]*LevelDiff `json:"by_level"`
}

func getOrCreateLevel(result *DiffResult, level int) *LevelDiff {
	if _, ok := result.ByLevel[level]; !ok {
		result.ByLevel[level] = &LevelDiff{
			Added:   []ComponentDiff{},
			Removed: []ComponentDiff{},
			Changed: []ComponentDiff{},
		}
	}

	return result.ByLevel[level]
}

// maxVulnScore returns the highest numeric score from vulns using the given getter.
func maxVulnScore(vulns []Vuln, getter func(Vuln) string) string {
	var maxF float64
	var result string
	for _, v := range vulns {
		val := getter(v)
		if val == "" {
			continue
		}
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			continue
		}
		if f > maxF {
			maxF = f
			result = val
		}
	}
	return result
}

func riskFields(comp Component) (maxCvss, maxEpss, maxLev string, severe bool) {
	maxCvss = maxVulnScore(comp.Vulns, func(v Vuln) string { return v.CVSSScore })
	maxEpss = maxVulnScore(comp.Vulns, func(v Vuln) string { return v.EPSS })
	maxLev = maxVulnScore(comp.Vulns, func(v Vuln) string { return v.LEV })
	severe = HasSevereVuln(comp.Vulns)
	return
}

// DiffSBOMs compares two FormattedSBOMs and returns added/removed/changed components grouped by level.
func DiffSBOMs(a, b FormattedSBOM) DiffResult {
	result := DiffResult{ByLevel: make(map[int]*LevelDiff)}

	for name, compA := range a.ComponentInfo {
		levelA := a.ComponentToLevel[name]
		cvssA, epssA, levA, severeA := riskFields(compA)

		compB, exists := b.ComponentInfo[name]
		if !exists {
			getOrCreateLevel(&result, levelA).Removed = append(
				getOrCreateLevel(&result, levelA).Removed,
				ComponentDiff{
					Name:       name,
					VersionA:   compA.Version,
					VulnsA:     compA.VulnNumber,
					HasVuln:    compA.VulnNumber > 0,
					HasVulnDep: compA.ContainsVulnDep,
					MaxCvssA:   cvssA,
					MaxEpssA:   epssA,
					MaxLevA:    levA,
					SevereA:    severeA,
				},
			)
			continue
		}

		cvssB, epssB, levB, severeB := riskFields(compB)
		levelB := b.ComponentToLevel[name]
		if compA.Version != compB.Version || compA.VulnNumber != compB.VulnNumber || levelA != levelB {
			diff := ComponentDiff{
				Name:       name,
				VersionA:   compA.Version,
				VersionB:   compB.Version,
				VulnsA:     compA.VulnNumber,
				VulnsB:     compB.VulnNumber,
				LevelA:     &levelA,
				LevelB:     &levelB,
				HasVuln:    compA.VulnNumber > 0 || compB.VulnNumber > 0,
				HasVulnDep: compA.ContainsVulnDep || compB.ContainsVulnDep,
				MaxCvssA:   cvssA,
				MaxCvssB:   cvssB,
				MaxEpssA:   epssA,
				MaxEpssB:   epssB,
				MaxLevA:    levA,
				MaxLevB:    levB,
				SevereA:    severeA,
				SevereB:    severeB,
			}

			getOrCreateLevel(&result, levelA).Changed = append(
				getOrCreateLevel(&result, levelA).Changed, diff,
			)
		}
	}

	for name, compB := range b.ComponentInfo {
		if _, exists := a.ComponentInfo[name]; !exists {
			levelB := b.ComponentToLevel[name]
			cvssB, epssB, levB, severeB := riskFields(compB)

			getOrCreateLevel(&result, levelB).Added = append(
				getOrCreateLevel(&result, levelB).Added,
				ComponentDiff{
					Name:       name,
					VersionB:   compB.Version,
					VulnsB:     compB.VulnNumber,
					HasVuln:    compB.VulnNumber > 0,
					HasVulnDep: compB.ContainsVulnDep,
					MaxCvssB:   cvssB,
					MaxEpssB:   epssB,
					MaxLevB:    levB,
					SevereB:    severeB,
				},
			)
		}
	}

	// compute vuln totals per level
	for _, ld := range result.ByLevel {

		for _, c := range ld.Removed {
			ld.TotalVulnsA += c.VulnsA
		}

		for _, c := range ld.Changed {
			ld.TotalVulnsA += c.VulnsA
			ld.TotalVulnsB += c.VulnsB
		}

		for _, c := range ld.Added {
			ld.TotalVulnsB += c.VulnsB
		}
	}

	return result
}
