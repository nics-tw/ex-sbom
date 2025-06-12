// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"errors"
	"ex-s/util/file"
	"ex-s/util/unique"
	"fmt"
	"log/slog"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

func ProcessCDX(name string, bom cdx.BOM, file []byte) error {
	if bom.BOMFormat != cdx.BOMFormat {
		return fmt.Errorf("invalid BOM format: %s", bom.BOMFormat)
	}

	if _, ok := SBOMs[name]; ok {
		// reset the sbom
		SBOMs[name] = FormattedSBOM{}
	}

	c := getCdxComponents(bom.Components)
	refToName := getCdxBomRefToName(bom.Components)

	dependency := getCdxDep(bom.Dependencies, refToName)
	dependencyLevel := getCdxDependencyDepthMap(bom, getCdxBomRef(bom.Components), refToName)

	SBOMs[name] = FormattedSBOM{
		Components:        c,
		DependencyLevel:   dependencyLevel,
		Dependency:        dependency,
		ReverseDependency: getReverseDep(dependency),
		ComponentToLevel:  getComponentToLevel(dependencyLevel),
		ComponentInfo:     getCdxComponentInfo(bom.Components, file, name),
	}

	withVuln := []string{}

	for compName, info := range SBOMs[name].ComponentInfo {
		if info.VulnNumber > 0 {
			withVuln = append(withVuln, compName)
		}
	}

	affecteds := []string{}

	for _, compName := range withVuln {
		affected := getAffecteds(compName, SBOMs[name].ReverseDependency)

		if len(affected) > 0 {
			affecteds = append(affecteds, affected...)
		}
	}

	distinct := unique.StringSlice(affecteds)

	for _, compName := range distinct {
		if _, ok := SBOMs[name]; !ok {
			slog.Error("failed to get name from refA", "refA", name)

			continue
		}

		componentInfo := SBOMs[name].ComponentInfo[compName]
		componentInfo.ContainsVulnDep = true
		// componentInfo.VulnDeps = append(componentInfo.VulnDeps, withVuln...)
		SBOMs[name].ComponentInfo[compName] = componentInfo
	}

	slog.Info(
		"Process CycloneDX-formatted SBOM successfully",
		"name",
		name,
		"numbers of components",
		len(c),
		"total levels",
		fmt.Sprintf("%d", len(SBOMs[name].DependencyLevel)),
	)

	return nil
}

func getCdxComponents(input *[]cdx.Component) []string {
	var components []string

	if input != nil {
		for _, c := range *input {
			components = append(components, c.Name)
		}
	}

	return unique.StringSlice(components)
}

func getCdxBomRef(input *[]cdx.Component) []string {
	var components []string

	if input != nil {
		for _, c := range *input {
			if c.BOMRef != "" {
				components = append(components, c.BOMRef)
			}
		}
	}

	return unique.StringSlice(components)
}

func getCdxBomRefToName(input *[]cdx.Component) map[string]string {
	components := make(map[string]string)

	if input != nil {
		for _, c := range *input {
			if c.BOMRef != "" {
				components[c.BOMRef] = c.Name
			}
		}
	}

	return components
}

func getCdxDependencyDepthMap(sbom cdx.BOM, allComponents []string, refToName map[string]string) map[int][]string {
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

	// perform DFS to calculate the depth of each node
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

	// considering with negative list way, if it's with depth that is not 0, that means it's not root
	roots = getRootComponents(allComponents, result)

	if len(result[0]) != 0  {
		// move components from current level to the next level
		for level := 0; level < len(result); level++ {
			if _, ok := result[level]; !ok {
				continue
			}

			for _, component := range result[level] {
				if _, ok := refToName[component]; !ok {
					slog.Error("failed to get ref name", "ref", component)
					continue
				}

				// if the component is not root, move it to the next level
				if !slices.Contains(roots, component) {
					result[level+1] = append(result[level+1], component)
				}
			}

			// clear the current level
			result[level] = nil
		}
	}

	// add the root components to level 0
	result[0] = append(result[0], roots...)

	// convert the ref to name
	converted := make(map[int][]string)

	for level, components := range result {
		for _, component := range components {
			name, ok := refToName[component]
			if !ok {
				slog.Error("failed to get ref name", "ref", component)
				continue
			}

			converted[level] = append(converted[level], name)
		}
	}

	return converted
}

func getCdxDep(input *[]cdx.Dependency, refToName map[string]string) map[string][]string {
	dependency := make(map[string][]string)

	if input != nil {
		for _, d := range *input {
			if d.Dependencies != nil && len(*d.Dependencies) > 0 {
				// convert the ref to name
				refName, ok := refToName[d.Ref]
				if !ok {
					slog.Error("failed to get ref name", "ref", d.Ref)
					continue
				}

				var deps []string
				for _, dep := range *d.Dependencies {
					depName, ok := refToName[dep]
					if !ok {
						slog.Error("failed to get dep name", "dep", dep)
						continue
					}
					deps = append(deps, depName)
				}

				dependency[refName] = deps
			}
		}
	}

	return dependency
}

func getCdxComponentInfo(input *[]cdx.Component, files []byte, filename string) map[string]Component {
	componentInfo := make(map[string]Component)

	path, err := file.CopyAndCreate(file.FileInput{
		Name:  filename,
		IsCDX: true,
		Data:  files,
	})
	if err != nil {
		slog.Error("failed to copy and create file", "error", err)

		return nil
	}

	vulnPkgs, err := file.GetScanResult(path)
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		slog.Error("failed to get scan result", "error", err)
	}

	if input != nil && len(*input) > 0 {
		for _, c := range *input {
			componentInfo[c.Name] = Component{
				Name:       c.Name,
				Version:    c.Version,
				VulnNumber: getVulnNumber(c.Name, vulnPkgs),
				Vulns:      getVulns(c.Name, c.Version, vulnPkgs),
			}
		}
	}

	file.Delete(path)

	return componentInfo
}
