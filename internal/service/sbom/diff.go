// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"math"
	"strconv"
)

// ComponentDiff represents a single component difference between two SBOMs.
type ComponentDiff struct {
	KeyB     string `json:"key_b,omitempty"`
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
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			continue
		}
		if result == "" || f > maxF {
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

type vulnRiskKey struct {
	id, cvss, epss, lev string
}

// sameVulnRisks compares findings as a multiset, so source ordering cannot
// produce a false diff and equal counts cannot hide changed findings.
func sameVulnRisks(a, b []Vuln) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[vulnRiskKey]int, len(a))
	for _, vuln := range a {
		counts[vulnRiskKey{vuln.ID, vuln.CVSSScore, vuln.EPSS, vuln.LEV}]++
	}
	for _, vuln := range b {
		key := vulnRiskKey{vuln.ID, vuln.CVSSScore, vuln.EPSS, vuln.LEV}
		if counts[key] == 0 {
			return false
		}
		counts[key]--
	}
	return true
}

type diffIdentity struct {
	name    string
	version string
}

type diffCandidates struct {
	key   string
	count int
}

func diffName(key string, component Component) string {
	if component.Name != "" {
		return component.Name
	}
	return key
}

func matchDiffComponents(a, b map[string]Component) (map[string]string, map[string]struct{}) {
	matches := make(map[string]string)
	matchedB := make(map[string]struct{})
	for key, compA := range a {
		if compB, ok := b[key]; ok && diffName(key, compA) == diffName(key, compB) && compA.Version == compB.Version {
			matches[key] = key
			matchedB[key] = struct{}{}
		}
	}

	// Aliases reflect the names present in one document and may change when
	// another package shares the same name. Match exact versions first to
	// retain survivors, then pair only unambiguous upgrades.
	for _, includeVersion := range []bool{true, false} {
		indexA := unmatchedDiffComponents(a, matches, includeVersion)
		indexB := unmatchedDiffComponents(b, matchedB, includeVersion)
		for identity, keysA := range indexA {
			keysB := indexB[identity]
			if keysA.count == 1 && keysB.count == 1 {
				matches[keysA.key] = keysB.key
				matchedB[keysB.key] = struct{}{}
			}
		}
	}
	return matches, matchedB
}

func unmatchedDiffComponents[T any](components map[string]Component, matched map[string]T, includeVersion bool) map[diffIdentity]diffCandidates {
	index := make(map[diffIdentity]diffCandidates)
	for key, component := range components {
		if _, ok := matched[key]; ok {
			continue
		}
		identity := diffIdentity{name: diffName(key, component)}
		if includeVersion {
			identity.version = component.Version
		}
		entry := index[identity]
		entry.key = key
		entry.count++
		index[identity] = entry
	}
	return index
}

// DiffSBOMs compares two FormattedSBOMs and returns added/removed/changed components grouped by level.
func DiffSBOMs(a, b FormattedSBOM) DiffResult {
	result := DiffResult{ByLevel: make(map[int]*LevelDiff)}
	matches, matchedB := matchDiffComponents(a.ComponentInfo, b.ComponentInfo)

	for name, compA := range a.ComponentInfo {
		levelA := a.ComponentToLevel[name]
		cvssA, epssA, levA, severeA := riskFields(compA)

		keyB, exists := matches[name]
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

		compB := b.ComponentInfo[keyB]
		cvssB, epssB, levB, severeB := riskFields(compB)
		levelB := b.ComponentToLevel[keyB]
		if compA.Version != compB.Version || compA.VulnNumber != compB.VulnNumber ||
			levelA != levelB || compA.ContainsVulnDep != compB.ContainsVulnDep ||
			!sameVulnRisks(compA.Vulns, compB.Vulns) {
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

			if keyB != name {
				diff.KeyB = keyB
			}
			getOrCreateLevel(&result, levelA).Changed = append(
				getOrCreateLevel(&result, levelA).Changed, diff,
			)
		}
	}

	for name, compB := range b.ComponentInfo {
		if _, exists := matchedB[name]; !exists {
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

	// Compare each snapshot at its own levels, including components with no diff row.
	totals := make(map[int][2]int)
	for name, component := range a.ComponentInfo {
		level := a.ComponentToLevel[name]
		counts := totals[level]
		counts[0] += component.VulnNumber
		totals[level] = counts
	}
	for name, component := range b.ComponentInfo {
		level := b.ComponentToLevel[name]
		counts := totals[level]
		counts[1] += component.VulnNumber
		totals[level] = counts
	}
	for level, counts := range totals {
		if result.ByLevel[level] != nil || counts[0] != counts[1] {
			ld := getOrCreateLevel(&result, level)
			ld.TotalVulnsA, ld.TotalVulnsB = counts[0], counts[1]
		}
	}

	return result
}
