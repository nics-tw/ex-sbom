package ssbom

import (
	"fmt"
	"slices"
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
		VulnNumber int    `json:"vuln_number"`
		Vulns      []Vuln `json:"vulns"`
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
	}
)

var (
	SBOMs = map[string]FormattedSBOM{}

	CVSSThreshold = int(7)
)

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

func getVulns(name string, vulnMap map[string]models.PackageVulns) []Vuln {
	if vuln, ok := vulnMap[name]; ok {
		var vulns []Vuln
		for _, v := range vuln.Vulnerabilities {

			vulns = append(vulns, Vuln{
				ID:                v.ID,
				Summary:           v.Summary,
				Details:           v.Details,
				CVSSScore:         getCVSS(v.ID, vuln.Groups),
				SuggestFixVersion: getFixVersion(v),
			})
		}

		return vulns
	}

	return nil
}

func getFixVersion(v osvschema.Vulnerability) string {
	var fixVersions strings.Builder

	for _, affected := range v.Affected {
		for _, r := range affected.Ranges {
			for _, e := range r.Events {
				if len(e.Fixed) > 0 {
					if fixVersions.Len() > 0 {
						fixVersions.WriteString(", ")
					}

					fixVersions.WriteString(e.Fixed)
				}
			}
		}
	}

	return fixVersions.String()
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
