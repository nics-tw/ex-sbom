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
	dependency := getCdxDep(bom.Dependencies)
	dependencyLevel := getCdxDependencyDepthMap(bom, c)

	SBOMs[name] = FormattedSBOM{
		Components:        c,
		DependencyLevel:   dependencyLevel,
		Dependency:        dependency,
		ReverseDependency: getReverseDep(dependency),
		ComponentToLevel:  getComponentToLevel(dependencyLevel),
		ComponentInfo:     getCdxComponentInfo(bom.Components, file, name),
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

func getCdxDependencyDepthMap(sbom cdx.BOM, allComponents []string) map[int][]string {
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
	result[0] = getRootComponents(allComponents, result)

	return result
}

func getCdxDep(input *[]cdx.Dependency) map[string][]string {
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

	if input != nil {
		for _, c := range *input {
			var num int
			vulns := make([]Vuln, 0)

			pkg, ok := vulnPkgs[c.Name]
			if ok {
				num = len(pkg.Vulnerabilities)

				if num > 0 {
					slog.Info("found vulnerabilities", "component", c.Name, "number", num)

					for _, v := range pkg.Vulnerabilities {
						vuln := Vuln{
							ID:      v.ID,
							Summary: v.Summary,
							Details: v.Details,
						}

						for _, g := range pkg.Groups {
							if slices.Contains(g.IDs, v.ID) {
								vuln.CVSSScore = g.MaxSeverity
							}
						}

						vulns = append(vulns, vuln)
					}
				}
			}

			componentInfo[c.Name] = Component{
				Name:       c.Name,
				Version:    c.Version,
				VulnNumber: num,
				Vulns:      vulns,
			}
		}
	}

	file.Delete(path)

	return componentInfo
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
