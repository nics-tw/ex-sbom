package ssbom

import (
	"ex-s/util/unique"
	"fmt"
	"log/slog"
	"strings"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

const (
	spdxPrefix        = "SPDXRef-"
	documentRefPrefix = "DocumentRef-"
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
	dependencyLevel := getSpdxDependencyDepthMap(*document, c)

	SBOMs[name] = FormattedSBOM{
		Components:        c,
		DependencyLevel:   dependencyLevel,
		Dependency:        dependency,
		ReverseDependency: getReverseDep(dependency),
		ComponentToLevel:  getComponentToLevel(dependencyLevel),
	}

	slog.Info(
		"Process SPDX-formatted SBOM successfully",
		"name",
		name,
		"numbers of components",
		len(c),
		"total levels",
		fmt.Sprintf("%d", len(SBOMs[name].DependencyLevel)),
	)

	return nil
}

func getSpdxDependencyDepthMap(sbom spdx.Document, allComponents []string) map[int][]string {
	graph := make(map[string][]string)
	inDegree := make(map[string]int)
	allNodes := make(map[string]bool)

	if len(sbom.Relationships) == 0 {
		return nil
	}

	for _, d := range sbom.Relationships {
		refAStr := trimSPDXPrefix(getRefIDStr(d.RefA))
		refBStr := trimSPDXPrefix(getRefIDStr(d.RefB))

		graph[refAStr] = append(graph[refAStr], refBStr)
		inDegree[refBStr]++
		allNodes[refAStr] = true
		allNodes[refBStr] = true
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
	return unique.StringSlice(components)
}

func getSpdxDep(input spdx.Document) map[string][]string {
	dependency := make(map[string][]string)

	if len(input.Relationships) != 0 {
		for _, r := range input.Relationships {
			dependency[trimSPDXPrefix(getRefIDStr(r.RefA))] =
				append(dependency[trimSPDXPrefix(getRefIDStr(r.RefA))], trimSPDXPrefix(getRefIDStr(r.RefB)))
		}
	}

	return dependency
}

func getRefIDStr(input common.DocElementID) string {
	if len(input.DocumentRefID) > 0 {
		return input.DocumentRefID
	} else if len(input.ElementRefID) > 0 {
		return string(input.ElementRefID)
	} else if len(input.SpecialID) > 0 {
		return input.SpecialID
	}

	return ""
}

func trimSPDXPrefix(input string) string {
	if strings.HasPrefix(input, "SPDXRef-") {
		return strings.TrimPrefix(input, "SPDXRef-")
	}

	if strings.HasPrefix(input, "DocumentRef-") {
		return strings.TrimPrefix(input, "DocumentRef-")
	}

	return input
}
