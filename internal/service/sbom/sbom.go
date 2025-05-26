package ssbom

import (
	"fmt"
	"log/slog"
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
		VulnNumber      int           `json:"vuln_number"`
		Vulns           []Vuln        `json:"vulns"`
		ContainsVulnDep bool          `json:"contains_vuln_dep"`
		VulnDeps        []string      `json:"vuln_deps"`
	}

	VulnDepPath struct {
		Name string `json:"name"`
		// Path is the path of the dependency in the original SBOM file
		// the first element is the dependency component with vuln, and the last element is the root component
		Path []string `json:"path"`
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
	return affected
}

func getVulnDepPaths(vulnComp string, ReverseDependency map[string][]string) []VulnDepPath {
	affecteds := getAffecteds(vulnComp, ReverseDependency)

	if len(affecteds) == 0 {
		return nil
	}

	var vulnDepPaths []VulnDepPath

	for _, affected := range affecteds {
		path := getPath(affected, vulnComp, ReverseDependency)
		if len(path) == 0 {
			slog.Error("failed to get path", "affected", affected, "vulnComp", vulnComp)
			continue
		}

		vulnDepPaths = append(vulnDepPaths, VulnDepPath{
			Name: vulnComp,
			Path: path,
		})
	}

	return vulnDepPaths
}

func getPath(comp, vulnComp string, ReverseDependency map[string][]string) []string {
    // path is defined as every package name that is in the path from the vulnComp to the root
    var path []string
    
    // If comp is the same as vulnComp, return just the component itself
    if comp == vulnComp {
        return []string{vulnComp}
    }
    
    // Use a map to track visited nodes and their parents
    visited := make(map[string]string)
    visited[vulnComp] = "" // vulnComp has no parent
    
    // Use BFS to find the shortest path from vulnComp to comp
    queue := []string{vulnComp}
    found := false
    
    for len(queue) > 0 && !found {
        current := queue[0]
        queue = queue[1:]
        
        // Check all components that depend on the current one
        for _, dependent := range ReverseDependency[current] {
            if _, seen := visited[dependent]; seen {
                continue
            }
            
            // Record that we got to dependent from current
            visited[dependent] = current
            
            if dependent == comp {
                found = true
                break
            }
            
            queue = append(queue, dependent)
        }
    }
    
    // If no path was found
    if !found {
        return nil
    }
    
    // Reconstruct the path from comp back to vulnComp
    reversePath := []string{}
    for current := comp; current != ""; current = visited[current] {
        reversePath = append(reversePath, current)
    }
    
    // Reverse the path to get from vulnComp to comp
    path = make([]string, len(reversePath))
    for i, c := range reversePath {
        path[len(reversePath)-1-i] = c
    }
    
    return path
}