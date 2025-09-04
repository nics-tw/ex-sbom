// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"errors"
	"ex-sbom/internal/service/lev"
	"ex-sbom/util"
	"ex-sbom/util/file"
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
	documentID         = "DOCUMENT"
	documentRootPrefix = "DocumentRoot-"
	filePrefix         = "File-"
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
	refToName := getSpdxIdentifierToName(*document)
	dependency := getSpdxDep(*document, refToName)
	dependencyLevel := getSpdxDependencyDepthMap(*document, c, refToName)

	SBOMs[name] = FormattedSBOM{
		Components:        c,
		DependencyLevel:   dependencyLevel,
		Dependency:        dependency,
		ReverseDependency: getReverseDep(dependency),
		ComponentToLevel:  getComponentToLevel(dependencyLevel),
		ComponentInfo:     getSpdxComponentInfo(*document, file, name),
	}

	compWithVuln := []string{}

	for compName, info := range SBOMs[name].ComponentInfo {
		if info.VulnNumber > 0 {
			compWithVuln = append(compWithVuln, compName)
		}
	}

	affecteds := []string{}

	for _, compName := range compWithVuln {
		affected := getAffecteds(compName, SBOMs[name].ReverseDependency)

		if len(affected) > 0 {
			affecteds = append(affecteds, affected...)
		}
	}

	distinct := util.StringSlice(affecteds)

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

func getSpdxDependencyDepthMap(sbom spdx.Document, allComponents []string, nameMap map[string]string) map[int][]string {
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

	roots = getRootComponents(allComponents, result)

	if len(result[0]) == 0 {
		var levels []int
		for level := range result {
			levels = append(levels, level)
		}

		slices.Sort(levels)

		for _, level := range levels {
			if level == 0 {
				continue
			}

			result[level-1] = result[level]
			delete(result, level)
		}
	}

	result[0] = append(result[0], roots...)

	convertedResult := make(map[int][]string)

	for level, components := range result {
		for _, component := range components {
			if name, ok := nameMap[component]; ok {
				convertedResult[level] = append(convertedResult[level], name)
			}
		}
	}

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
	return util.StringSlice(components)
}

func getSpdxIdentifierToName(input spdx.Document) map[string]string {
	components := make(map[string]string)

	for _, p := range input.Packages {
		if p.PackageSPDXIdentifier != "" && !isGeneratedRoot(string(p.PackageSPDXIdentifier)) {
			components[string(p.PackageSPDXIdentifier)] = p.PackageName
		}
	}

	return components
}

func getSpdxDep(input spdx.Document, nameMap map[string]string) map[string][]string {
	dependency := make(map[string][]string)

	if len(input.Relationships) != 0 {
		for _, r := range input.Relationships {
			refA := trimSPDXPrefix(getRefIDStr(r.RefA))
			refB := trimSPDXPrefix(getRefIDStr(r.RefB))

			if isGeneratedRoot(refA) || isGeneratedRoot(refB) {
				continue
			}

			nameA, ok := nameMap[getRefIDStr(r.RefA)]
			if !ok {
				slog.Error("failed to get name from refA", "refA", refA)

				continue
			}

			nameB, ok := nameMap[getRefIDStr(r.RefB)]
			if !ok {
				slog.Error("failed to get name from refB", "refB", refB)

				continue
			}

			dependency[nameA] = append(dependency[nameA], nameB)
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

	trimmedVulnPkgs := trimPublicationPrefix(vulnPkgs)

	for _, p := range input.Packages {
		if p.PackageSPDXIdentifier != "" {
			result[string(p.PackageSPDXIdentifier)] = Component{
				Name:       p.PackageName,
				Version:    p.PackageVersion,
				VulnNumber: getVulnNumber(p.PackageName, trimmedVulnPkgs),
				Vulns:      getVulns(p.PackageName, p.PackageVersion, trimmedVulnPkgs),
				Licences:   getSpdxLicences(p.PackageLicenseDeclared),
			}
		}
	}

	var cves []string

	for _, c := range result {
		for _, v := range c.Vulns {
			if v.ID != "" {
				cves = append(cves, v.ID)
			}
		}
	}

	firstInfos, err := lev.GetByChunk(cves)
	if err != nil {
		slog.Error("failed to get lev info", "error", err)
	}

	if len(firstInfos) == 0 {
		slog.Info("no lev info found for the components", "name", filename)
	}

	for name, info := range result {
		updated := false
		for i, v := range info.Vulns {
			if data, found := firstInfos[v.ID]; found {
				slog.Info("found lev info", "cve", v.ID, "lev", data.LEV, "epss", data.EPSS)
				info.Vulns[i].EPSS = fmt.Sprintf("%.6f", data.EPSSNum)
				info.Vulns[i].LEV = fmt.Sprintf("%.6f", data.LEV)
				updated = true
			}
		}
		if updated {
			result[name] = info
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
	return input == documentID || strings.HasPrefix(input, documentRootPrefix) || strings.HasPrefix(input, filePrefix)
}

// some document will have publication naming as prefix for the component name containing vulnerability
// for example, `maven:guava`
// but the vulnerability database will only contain the component name without the prefix
// so we need to trim the prefix for better matching
func trimPublicationPrefix(pkgMap map[string]models.PackageVulns) map[string]models.PackageVulns {
	var result = make(map[string]models.PackageVulns)

	for k, v := range pkgMap {
		if strings.Contains(k, ":") {
			parts := strings.SplitN(k, ":", 2)

			result[parts[1]] = v
		}

		result[k] = v
	}

	return result
}

func getSpdxLicences(licenceInfo string) string {
	if len(licenceInfo) == 0 || licenceInfo == "NOASSERTION" {
		return licenceInfo
	}

	return licenceInfo
}
