// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"ex-sbom/util/unique"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type (
	// FormattedSBOM is a struct that contains the formatted SBOM data, which is originally in SPDX or CycloneDX defined format.
	FormattedSBOM struct {
		Components      []string
		DependencyLevel map[int][]string
		Dependency      map[string][]string
		// Reverse dependency is designed for finding out the components that depend on a specific component
		// in this case the specific one with vuln that the CVSS score is higher than 7(or user defined)
		ReverseDependency map[string][]string
		// ComponentToLevel is an map with util designed for finding out the level of a specific component
		// in this case it is used for topology drawing
		ComponentToLevel map[string]int
		ComponentInfo    map[string]Component
	}

	// Component is a struct that contains the information from both the original SBOM file and scanned info from the osv-scanner util
	Component struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		// VulnNumber is the number of total vulnerabilities that the component has
		VulnNumber      int    `json:"vuln_number"`
		Vulns           []Vuln `json:"vulns"`
		ContainsVulnDep bool   `json:"contains_vuln_dep"`
	}

	VlunDepPath struct {
		Start string   `json:"start"`
		End   string   `json:"end"`
		Path  []string `json:"path"`
	}

	// Vuln is a struct that contains the information of the vulnerability within the component(if existing)
	Vuln struct {
		ID      string `json:"id"`
		Summary string `json:"summary"`
		// Details is the description of the vulnerability, which is in markdown format, including root cause and patch information
		Details   string `json:"details"`
		CVSSScore string `json:"cvss_score"`
		// SuggestFixVersion is a distinct list of versions that the user can upgrade to prevent the vulnerability
		// here concat the versions with ", " as the separator

		SuggestFixVersion string `json:"suggest_fix_version"`
		OtherFixVersions  string `json:"other_fix_versions"`

		FixVersions []string `json:"-"`
	}

	version struct {
		Original string `json:"original"`
		Parts    []int  `json:"parts"`
	}
)

var (
	SBOMs = map[string]FormattedSBOM{}

	CVSSThreshold = float64(7)
)

func (bom FormattedSBOM) GetVulnComponents() []string {
	var vulnComponents []string

	for compName, info := range bom.ComponentInfo {
		if info.VulnNumber > 0 {
			vulnComponents = append(vulnComponents, compName)
		}
	}

	return vulnComponents
}

func GetSBOM(name string) (FormattedSBOM, error) {
	sbom, ok := SBOMs[name]
	if !ok {
		return FormattedSBOM{}, fmt.Errorf("SBOM not found")
	}

	return sbom, nil
}

func DeleteSBOM(name string) {
	delete(SBOMs, name)
}

func GetVulnDepPaths(startComp string, endComps []string, depMap map[string][]string) []VlunDepPath {
	var paths []VlunDepPath

	// If startComp is not in depMap, return empty slice
	if _, ok := depMap[startComp]; !ok {
		return paths
	}

	for _, endComp := range endComps {
		// Skip if start and end are the same
		if startComp == endComp {
			continue
		}

		// Reset path and visited map for each end component
		var path []string
		visited := make(map[string]bool)

		// Recursively find the path from startComp to endComp
		var findPath func(current string) bool
		findPath = func(current string) bool {
			// Prevent cycles by checking if node was already visited
			if visited[current] {
				return false
			}
			visited[current] = true

			if current == endComp {
				path = append(path, current)
				return true
			}

			// Safely check if the current component exists in depMap
			deps, ok := depMap[current]
			if !ok {
				return false
			}

			for _, next := range deps {
				if findPath(next) {
					path = append([]string{current}, path...)
					return true
				}
			}

			return false
		}

		// Only proceed if path was found
		if findPath(startComp) {
			paths = append(paths, VlunDepPath{
				Start: startComp,
				End:   endComp,
				Path:  path,
			})
		}
	}

	return paths
}

// 1. purge the versions that are lower than the current version
// 2. find the smallest version of each array
// 3. return the biggest version from the result of step 2
// If there are no versions higher than the current version, return an empty string
func GetSuggestFixVersions(current string, versions ...[]string) string {
	currentVer := parseVersion(current)
	var candidates []version

	// Process each version array
	for _, verList := range versions {
		var higherVersions []version

		// Filter to only keep versions higher than current
		for _, ver := range verList {
			parsedVer := parseVersion(ver)
			if compareVersions(parsedVer, currentVer) > 0 {
				higherVersions = append(higherVersions, parsedVer)
			}
		}

		// If we have higher versions, find the smallest
		if len(higherVersions) > 0 {
			// Sort in ascending order
			sort.Slice(higherVersions, func(i, j int) bool {
				return compareVersions(higherVersions[i], higherVersions[j]) < 0
			})

			// Add the smallest to candidates
			candidates = append(candidates, higherVersions[0])
		}
	}

	// If no candidates, return empty string
	if len(candidates) == 0 {
		return ""
	}

	// Find the biggest among the candidates
	sort.Slice(candidates, func(i, j int) bool {
		return compareVersions(candidates[i], candidates[j]) > 0 // Sort in descending order
	})

	// Return the original string of the highest version
	return candidates[0].Original
}

func IsBreakingChange(current, suggest string) bool {
	currentVer := parseVersion(current)
	suggestVer := parseVersion(suggest)

	// Compare major versions
	if len(currentVer.Parts) > 0 && len(suggestVer.Parts) > 0 &&
		currentVer.Parts[0] != suggestVer.Parts[0] {
		return true
	}

	return false
}

func HasSevereVuln(vulns []Vuln) bool {
	var hasSevere bool

	for _, v := range vulns {
		if v.CVSSScore != "" {
			score, err := strconv.ParseFloat(v.CVSSScore, 64)
			if err == nil && score >= CVSSThreshold {
				hasSevere = true
				break
			}
		}
	}

	return hasSevere
}

func IsSevereVuln(v Vuln) bool {
	if v.CVSSScore == "" {
		return false
	}

	score, err := strconv.ParseFloat(v.CVSSScore, 64)
	if err != nil {
		return false
	}

	return score >= CVSSThreshold
}

func getComponentToLevel(DependencyLevel map[int][]string) map[string]int {
	componentToLevel := make(map[string]int)

	for level, components := range DependencyLevel {
		for _, component := range components {
			componentToLevel[component] = level
		}
	}

	return componentToLevel
}

func getCVSS(id string, groups []models.GroupInfo) string {
	for _, g := range groups {
		if slices.Contains(g.IDs, id) {
			return g.MaxSeverity
		}
	}

	return ""
}

func getVulnNumber(name string, vulnMap map[string]models.PackageVulns) int {
	if vuln, ok := vulnMap[name]; ok {
		return len(vuln.Vulnerabilities)
	}

	return 0
}

func getVulns(name string, version string, vulnMap map[string]models.PackageVulns) []Vuln {
	if vuln, ok := vulnMap[name]; ok {
		var vulns []Vuln
		for _, v := range vuln.Vulnerabilities {
			allFixVers := getAllFixVersions(v)
			suggestFix := findNearestVersions(version, allFixVers)
			otherFixVer := getDiff(allFixVers, suggestFix)

			vulns = append(vulns, Vuln{
				ID:                v.ID,
				Summary:           v.Summary,
				Details:           v.Details,
				CVSSScore:         getCVSS(v.ID, vuln.Groups),
				SuggestFixVersion: getVersionString(suggestFix),
				OtherFixVersions:  getVersionString(otherFixVer),

				FixVersions: getAllFixVersions(v),
			})
		}

		return vulns
	}

	return nil
}

func getVersionString(strs []string) string {
	if len(strs) == 0 {
		return ""
	}

	var version strings.Builder
	for i, s := range strs {
		if i > 0 {
			version.WriteString(", ")
		}
		version.WriteString(s)
	}

	return version.String()
}

func getAllFixVersions(v osvschema.Vulnerability) []string {
	var fixVersions []string

	for _, affected := range v.Affected {
		for _, r := range affected.Ranges {
			for _, e := range r.Events {
				if len(e.Fixed) > 0 && !slices.Contains(fixVersions, e.Fixed) {
					fixVersions = append(fixVersions, e.Fixed)
				}
			}
		}
	}

	return fixVersions
}

func getReverseDep(Dependency map[string][]string) map[string][]string {
	// TODO: calculate non-root package number for pre-allocate the slice
	reverseDependency := make(map[string][]string)

	for k, v := range Dependency {
		for _, dep := range v {
			if _, ok := reverseDependency[dep]; !ok {
				reverseDependency[dep] = []string{}
			}
			reverseDependency[dep] = append(reverseDependency[dep], k)
		}
	}

	return reverseDependency
}

func getRootComponents(allComponents []string, depthMap map[int][]string) []string {
	var nonRoots []string

	for _, components := range depthMap {
		nonRoots = append(nonRoots, components...)
	}

	return getDiff(allComponents, nonRoots)
}

func getDiff(a, b []string) []string {
	bMap := make(map[string]struct{}, len(b))
	for _, itemB := range b {
		bMap[itemB] = struct{}{}
	}

	result := make([]string, 0, len(a))
	for _, itemA := range a {
		if _, exists := bMap[itemA]; !exists {
			result = append(result, itemA)
		}
	}

	return result
}

// getAffecteds is a util function that returns the components that have direct or indirect relationship with the given component
func getAffecteds(name string, ReverseDependency map[string][]string) []string {
	seen := make(map[string]bool)
	var affected []string

	var traverse func(component string)
	traverse = func(component string) {
		if seen[component] {
			return
		}
		seen[component] = true

		deps, ok := ReverseDependency[component]
		if !ok || len(deps) == 0 {
			return
		}

		for _, dep := range deps {
			affected = append(affected, dep)
			traverse(dep)
		}
	}

	traverse(name)
	return unique.StringSlice(affected)
}

func parseVersion(v string) version {
	if len(v) > 0 && rune(v[0]) == 'v' {
		v = v[1:]
	}

	// Split by periods to get version segments
	parts := strings.Split(v, ".")
	intParts := make([]int, len(parts))

	for i, p := range parts {
		// Extract only the numeric prefix from each part
		numericPrefix := ""
		for _, char := range p {
			if char >= '0' && char <= '9' {
				numericPrefix += string(char)
			} else {
				// Stop at first non-numeric character
				break
			}
		}

		// Convert the numeric prefix to integer
		if numericPrefix != "" {
			intParts[i], _ = strconv.Atoi(numericPrefix)
		}
	}

	return version{Original: v, Parts: intParts}
}

// Compare a < b: -1, a == b: 0, a > b: 1
func compareVersions(a, b version) int {
	for i := 0; i < len(a.Parts) && i < len(b.Parts); i++ {
		if a.Parts[i] < b.Parts[i] {
			return -1
		} else if a.Parts[i] > b.Parts[i] {
			return 1
		}
	}

	if len(a.Parts) < len(b.Parts) {
		return -1
	} else if len(a.Parts) > len(b.Parts) {
		return 1
	}

	return 0
}

func findNearestVersions(target string, versions []string) []string {
	targetVersion := parseVersion(target)
	var sameMajorHigher []version      // Same major version and higher than target
	var differentMajorHigher []version // Different major version and higher than target
	allOlder := true

	for _, v := range versions {
		ver := parseVersion(v)
		cmp := compareVersions(ver, targetVersion)

		if cmp > 0 { // Higher version
			allOlder = false

			// Check if same major
			if len(ver.Parts) > 0 && len(targetVersion.Parts) > 0 &&
				ver.Parts[0] == targetVersion.Parts[0] {
				sameMajorHigher = append(sameMajorHigher, ver)
			} else {
				differentMajorHigher = append(differentMajorHigher, ver)
			}
		} else if cmp == 0 { // Equal version
			allOlder = false
		}
	}

	// If all versions are older, return empty slice
	if allOlder {
		return nil
	}

	// Sort versions in ascending order
	sort.Slice(sameMajorHigher, func(i, j int) bool {
		return compareVersions(sameMajorHigher[i], sameMajorHigher[j]) < 0
	})
	sort.Slice(differentMajorHigher, func(i, j int) bool {
		return compareVersions(differentMajorHigher[i], differentMajorHigher[j]) < 0
	})

	var result []string

	// Add lowest same major version (if any)
	if len(sameMajorHigher) > 0 {
		result = append(result, sameMajorHigher[0].Original)
	}

	// Add lowest different major version (if any)
	if len(differentMajorHigher) > 0 {
		result = append(result, differentMajorHigher[0].Original)
	}

	return result
}
