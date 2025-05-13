package ssbom

import (
	"errors"
	"ex-s/util/file"
	"ex-s/util/unique"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

const (
	spdxPrefix         = "SPDXRef-"
	documentRefPrefix  = "DocumentRef-"
	documentID         = "DOCUMENT"
	documentRootPrefix = "DocumentRoot-"
)

func ProcessSPDX(name string, document *spdx.Document, file []byte) error {
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
		ComponentInfo:     getSpdxComponentInfo(*document, file, name),
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

		if isGeneratedRoot(refAStr) || isGeneratedRoot(refBStr) {
			continue
		}

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
		if p.PackageSPDXIdentifier != "" && !isGeneratedRoot(string(p.PackageSPDXIdentifier)) {
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
			refA := trimSPDXPrefix(getRefIDStr(r.RefA))
			refB := trimSPDXPrefix(getRefIDStr(r.RefB))

			if isGeneratedRoot(refA) || isGeneratedRoot(refB) {
				continue
			}

			dependency[refA] = append(dependency[refA], refB)
		}
	}

	return dependency
}

func getSpdxComponentInfo(input spdx.Document, files []byte, filename string) map[string]Component {
	var result = make(map[string]Component)

	path, err := file.CopyAndCreate(file.FileInput{
		Name:  filename,
		IsCDX: false,
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

	for _, p := range input.Packages {
		if p.PackageSPDXIdentifier != "" {
			result[string(p.PackageSPDXIdentifier)] = Component{
				Name:       p.PackageName,
				Version:    p.PackageVersion,
				VulnNumber: getVulnNumber(p.PackageName, vulnPkgs),
				Vulns:      getVulns(p.PackageName, vulnPkgs),
			}
		}
	}

	file.Delete(path)

	return result
}

// the implement of the common.DocElementID interface containing three possible ID
// in these case we only apply the one that only exists as the unique ID for the purpose of handy mapping
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

// for the original SPDX file, the SPDXREFID will contain two kinds of prefix
// 1. SPDXRef-: the one that is used for the component itself
// 2. DocumentRef-: the one that is used for the ducumentation itself
// but on the other hand, while processing other util, it will trim these prefix if existing
// since not all columns performed the same pattern(and most of them applied with the one witout prefix)
// this util function is for aligning the pattern in using unique id for SPDX document
func trimSPDXPrefix(input string) string {
	if strings.HasPrefix(input, "SPDXRef-") {
		return strings.TrimPrefix(input, "SPDXRef-")
	}

	if strings.HasPrefix(input, "DocumentRef-") {
		return strings.TrimPrefix(input, "DocumentRef-")
	}

	return input
}

// default spdx document will consider the document itself as a component
// for better understanding and preventing confusion, we will ignore it as default
func isGeneratedRoot(input string) bool {
	return input == documentID || strings.HasPrefix(input, documentRootPrefix)
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
				ID:        v.ID,
				Summary:   v.Summary,
				Details:   v.Details,
				CVSSScore: getCVSS(v.ID, vuln.Groups),
			})
		}

		return vulns
	}

	return nil
}
