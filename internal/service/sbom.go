package service

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type (
	FormattedSBOM struct {
		Components      []string
		DependencyLevel map[int][]string
		Dependency      map[string][]string
		// Reverse dependency is designed for finding out the components that depend on a specific component
		// in this case the specific one with vuln that the CVSS score is higher than 7(or user defined)
		ReverseDependency map[string][]string
	}
)

var (
	SBOMs = map[string]FormattedSBOM{}

	CVSSThreshold = int(7)
)

func ProcessCDX(name string, bom cdx.BOM) error {
	if bom.BOMFormat != cdx.BOMFormat {
		return fmt.Errorf("invalid BOM format: %s", bom.BOMFormat)
	}

	if _, ok := SBOMs[name]; ok {
		// reset the sbom
		SBOMs[name] = FormattedSBOM{}
	}

	dependency := getDep(bom.Dependencies)

	SBOMs[name] = FormattedSBOM{
		Components:        getComponents(bom.Components),
		DependencyLevel:   getDependencyDepthMap(bom),
		Dependency:        dependency,
		ReverseDependency: getReverseDep(dependency),
	}

	return nil
}

func DeleteSBOM(name string) {
	delete(SBOMs, name)
}

func getComponents(input *[]cdx.Component) []string {
	var components []string

	if input != nil {
		for _, c := range *input {
			components = append(components, c.Name)
		}
	}

	return components
}

func getDependencyDepthMap(sbom cdx.BOM) map[int][]string {
	graph := make(map[string][]string)
	inDegree := make(map[string]int)
	allNodes := make(map[string]bool)

	if sbom.Dependencies != nil && len(*sbom.Dependencies) != 0 {
		for _, d := range *sbom.Dependencies {
			if d.Dependencies != nil && len(*d.Dependencies) > 0 {
				allNodes[d.Ref] = true
				for _, dep := range *d.Dependencies {
					graph[d.Ref] = append(graph[d.Ref], dep)
					inDegree[dep]++
					allNodes[dep] = true
				}
			}
		}
	}

	var roots []string
	for node := range allNodes {
		if inDegree[node] == 0 {
			roots = append(roots, node)
		}
	}

	depthMap := make(map[string]int)

	var dfs func(node string, depth int)
	dfs = func(node string, depth int) {
		if depth > depthMap[node] {
			depthMap[node] = depth
		}
		for _, neighbor := range graph[node] {
			dfs(neighbor, depth+1)
		}
	}

	for _, root := range roots {
		dfs(root, 0)
	}

	result := make(map[int][]string)
	for node, depth := range depthMap {
		result[depth] = append(result[depth], node)
	}

	result[0] = roots

	return result
}

func getDep(input *[]cdx.Dependency) map[string][]string {
	dependency := make(map[string][]string)

	if input != nil {
		for _, d := range *input {
			if d.Dependencies != nil && len(*d.Dependencies) > 0 {
				dependency[d.Ref] = append(dependency[d.Ref], *d.Dependencies...)
			}
		}
	}

	return dependency
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
