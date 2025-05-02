package ssbom

import (
	"fmt"
	"slices"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

func ProcessSPDX(name string, document *spdx.Document) error {
	if document == nil {
		return nil
	}

	if _, ok := SBOMs[name]; ok {
		// reset the sbom
		SBOMs[name] = FormattedSBOM{}
	}

	c := getSpdxComponents(*document)
	dependency := getSpdxDep(*document)

	SBOMs[name] = FormattedSBOM{
		Components:        c,
		DependencyLevel:   getSpdxDependencyDepthMap(*document, c),
		Dependency:        dependency,
		ReverseDependency: getReverseDep(dependency),
	}

	return nil
}

func getSpdxDependencyDepthMap(sbom spdx.Document, allComponents []string) map[int][]string {
	graph := make(map[common.DocElementID][]common.DocElementID)
	inDegree := make(map[common.DocElementID]int)
	allNodes := make(map[common.DocElementID]bool)

	if len(sbom.Relationships) == 0 {
		return nil
	}

	for _, d := range sbom.Relationships {
		graph[d.RefA] = append(graph[d.RefA], d.RefB)
		inDegree[d.RefB]++
		allNodes[d.RefA] = true
		allNodes[d.RefB] = true
	}

	var roots []common.DocElementID

	for node := range allNodes {
		if inDegree[node] == 0 {
			roots = append(roots, node)
		}
	}

	depthMap := make(map[common.DocElementID]int)

	var dfs func(node common.DocElementID, depth int)
	dfs = func(node common.DocElementID, depth int) {
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
		str := fmt.Sprintf("%s", node)

		result[depth] = append(result[depth], str)
	}

	result[0] = getRootComponents(allComponents, result)

	return result
}

func getSpdxComponents(input spdx.Document) []string {
	var components []string

	for _, p := range input.Packages {
		if p.PackageSPDXIdentifier != "" {
			components = append(components, string(p.PackageSPDXIdentifier))
		}
	}

	// Currently there's some bugs that will result in duplicated package information existing at the same time for some SBOM scanning tool
	// ref: https://github.com/aquasecurity/trivy/issues/7824
	return slices.Compact(components)
}

func getSpdxDep(input spdx.Document) map[string][]string {
	dependency := make(map[string][]string)

	if len(input.Relationships) != 0 {
		for _, r := range input.Relationships {
			refAStr := fmt.Sprintf("%s", r.RefA)
			refBStr := fmt.Sprintf("%s", r.RefB)

			dependency[refAStr] = append(dependency[refAStr], refBStr)
		}
	}

	return dependency
}
