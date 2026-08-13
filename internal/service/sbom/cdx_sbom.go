// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/service/lev"
	"ex-sbom/util"
	"ex-sbom/util/file"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

func buildCDXResult(bom cdx.BOM, rawData []byte, name string) (FormattedSBOM, string, time.Time) {
	refToName := getCdxBomRefToName(bom.Components)

	// metadata.component represents the application being described, not a real
	// dependency. Mirror SPDX's treatment of SPDXRef-DOCUMENT: register the ref so
	// it stays resolvable, but filter it from the dependency graph so level 0 is
	// the application's direct dependencies.
	var rootRef string
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		mc := bom.Metadata.Component
		if mc.BOMRef != "" && mc.Name != "" {
			refToName[mc.BOMRef] = mc.Name
			rootRef = mc.BOMRef
		}
	}

	// Resolve any BOMRefs that appear in the dependency graph but are not listed
	// as standalone components (e.g. .NET project references). Names are derived
	// from the BOMRef using nameFromBOMRef.
	resolveMissingRefs(bom.Dependencies, refToName)

	c := getCdxComponents(bom.Components)
	dependency := getCdxDep(bom.Dependencies, refToName, rootRef)
	dependencyLevel := getCdxDependencyDepthMap(bom, getCdxBomRef(bom.Components), refToName, rootRef)

	result := FormattedSBOM{
		Components:        c,
		DependencyLevel:   dependencyLevel,
		Dependency:        dependency,
		ReverseDependency: getReverseDep(dependency),
		ComponentToLevel:  getComponentToLevel(dependencyLevel),
		ComponentInfo:     getCdxComponentInfo(bom.Components, rawData, name),
	}

	withVuln := []string{}
	for compName, info := range result.ComponentInfo {
		if info.VulnNumber > 0 {
			withVuln = append(withVuln, compName)
		}
	}

	affecteds := []string{}
	for _, compName := range withVuln {
		affected := getAffecteds(compName, result.ReverseDependency)
		if len(affected) > 0 {
			affecteds = append(affecteds, affected...)
		}
	}

	distinct := util.StringSlice(affecteds)
	for _, compName := range distinct {
		componentInfo := result.ComponentInfo[compName]
		componentInfo.ContainsVulnDep = true
		result.ComponentInfo[compName] = componentInfo
	}

	var bomTimestamp time.Time
	if bom.Metadata != nil && bom.Metadata.Timestamp != "" {
		bomTimestamp, _ = time.Parse(time.RFC3339, bom.Metadata.Timestamp)
	}

	sortFormattedSBOM(&result)
	sha256Hash := HashSBOM(result)

	return result, sha256Hash, bomTimestamp
}

func (s *Service) ProcessCDX(projectID domain.ProjectID, name domain.Version, bom cdx.BOM, rawData []byte) error {
	if bom.BOMFormat != cdx.BOMFormat {
		return fmt.Errorf("invalid BOM format: %s", bom.BOMFormat)
	}

	final, sha256Hash, bomTimestamp := buildCDXResult(bom, rawData, name)

	unlock := s.cache.LockProject(projectID)
	s.cache.Set(projectID, name, final)
	if err := s.repo.CreateSBOM(projectID, name, final, bomTimestamp, sha256Hash); err != nil {
		slog.Error("Failed to save SBOM to DB", "error", err)
	}
	unlock()

	slog.Info(
		"Process CycloneDX-formatted SBOM successfully",
		"name", name,
		"numbers of components", len(final.Components),
		"total levels", fmt.Sprintf("%d", len(final.DependencyLevel)),
	)

	return nil
}

func (s *Service) PreviewCDX(bom cdx.BOM, rawData []byte) (FormattedSBOM, string, time.Time, error) {
	if bom.BOMFormat != cdx.BOMFormat {
		return FormattedSBOM{}, "", time.Time{}, fmt.Errorf("invalid BOM format: %s", bom.BOMFormat)
	}

	final, sha256Hash, bomTimestamp := buildCDXResult(bom, rawData, "preview")
	return final, sha256Hash, bomTimestamp, nil
}

// nameFromBOMRef extracts a human-readable name from a BOM reference.
// For purl-formatted refs (e.g. pkg:nuget/WebSite@latest), it extracts the package name.
// Falls back to the raw ref string if no pattern matches.
func nameFromBOMRef(ref string) string {
	if !strings.HasPrefix(ref, "pkg:") {
		return ref
	}

	// purl format: pkg:type/[namespace/]name[@version]
	// Strip "pkg:type/" prefix to get "[namespace/]name[@version]"
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) < 2 {
		return ref
	}

	nameWithVersion := parts[1]

	// Remove version suffix (@version)
	if idx := strings.Index(nameWithVersion, "@"); idx != -1 {
		nameWithVersion = nameWithVersion[:idx]
	}

	// Take the last path segment (handles namespace/name)
	segments := strings.Split(nameWithVersion, "/")
	return segments[len(segments)-1]
}

// resolveMissingRefs adds BOMRef→name mappings for any refs that appear in the
// dependency graph but are not already in refToName. This covers project references
// (e.g. .NET projects) that act as dependency intermediaries but are not listed
// as standalone components. Names are derived from the BOMRef via nameFromBOMRef.
func resolveMissingRefs(deps *[]cdx.Dependency, refToName map[string]string) {
	if deps == nil {
		return
	}

	for _, d := range *deps {
		if d.Ref != "" {
			if _, ok := refToName[d.Ref]; !ok {
				refToName[d.Ref] = nameFromBOMRef(d.Ref)
			}
		}

		if d.Dependencies == nil {
			continue
		}

		for _, dep := range *d.Dependencies {
			if _, ok := refToName[dep]; !ok {
				refToName[dep] = nameFromBOMRef(dep)
			}
		}
	}
}

func getCdxComponents(input *[]cdx.Component) []string {
	var components []string

	if input != nil {
		for _, c := range *input {
			components = append(components, c.Name)
		}
	}

	return util.StringSlice(components)
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

	return util.StringSlice(components)
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

func getCdxDependencyDepthMap(sbom cdx.BOM, allComponents []string, refToName map[string]string, rootRef string) map[int][]string {
	graph := make(map[string][]string)
	inDegree := make(map[string]int)
	allNodes := make(map[string]bool)

	for _, ref := range allComponents {
		allNodes[ref] = true
		inDegree[ref] = 0
	}

	if sbom.Dependencies != nil {
		for _, d := range *sbom.Dependencies {
			// Skip the synthetic root app: register its direct deps so they become
			// level-0 nodes, but do not create rootRef→child edges or add rootRef
			// as a node. This aligns CDX behavior with SPDX's isGeneratedRoot.
			if d.Ref == rootRef && rootRef != "" {
				if d.Dependencies != nil {
					for _, dep := range *d.Dependencies {
						allNodes[dep] = true
					}
				}
				continue
			}

			if d.Ref != "" {
				allNodes[d.Ref] = true
			}

			if d.Dependencies == nil {
				continue
			}

			for _, dep := range *d.Dependencies {
				graph[d.Ref] = append(graph[d.Ref], dep)
				inDegree[dep]++
				allNodes[dep] = true
			}
		}
	}

	// BFS from all root nodes (in-degree = 0)
	levelMap := make(map[string]int)
	visited := make(map[string]bool)
	queue := make([]struct {
		node  string
		level int
	}, 0)

	for node := range allNodes {
		if inDegree[node] == 0 {
			queue = append(queue, struct {
				node  string
				level int
			}{node, 0})
			visited[node] = true
		}
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		levelMap[current.node] = current.level

		for _, neighbor := range graph[current.node] {
			if !visited[neighbor] {
				visited[neighbor] = true
				queue = append(queue, struct {
					node  string
					level int
				}{neighbor, current.level + 1})
			}
		}
	}

	// Convert ref-based level map to name-based result.
	// refToName is guaranteed complete after resolveMissingRefs, so missing keys
	// indicate an unexpected ref — log a warning and skip.
	result := make(map[int][]string)

	for node, level := range levelMap {
		name, ok := refToName[node]
		if !ok {
			slog.Warn("unresolved BOMRef in dependency graph", "ref", node)
			continue
		}
		result[level] = append(result[level], name)
	}

	for ref := range allNodes {
		if !visited[ref] {
			name, ok := refToName[ref]
			if !ok {
				slog.Warn("unresolved isolated BOMRef", "ref", ref)
				continue
			}
			result[0] = append(result[0], name)
		}
	}

	// Re-index levels to remove gaps.
	finalResult := make(map[int][]string)
	nextLevel := 0

	for level := 0; level < len(result)+1; level++ {
		if components, ok := result[level]; ok && len(components) > 0 {
			finalResult[nextLevel] = components
			nextLevel++
		}
	}

	return finalResult
}

func getCdxDep(input *[]cdx.Dependency, refToName map[string]string, rootRef string) map[string][]string {
	dependency := make(map[string][]string)

	if input == nil {
		return dependency
	}

	for _, d := range *input {
		// The metadata.component is a synthetic root describing the application
		// itself; its "depends on" edges are promoted to level-0 by the depth map
		// builder, so exclude them from the Dependency adjacency list.
		if d.Ref == rootRef && rootRef != "" {
			continue
		}

		if d.Dependencies == nil || len(*d.Dependencies) == 0 {
			continue
		}

		refName, ok := refToName[d.Ref]
		if !ok {
			slog.Warn("unresolved BOMRef in dependency list", "ref", d.Ref)
			continue
		}

		var deps []string
		for _, dep := range *d.Dependencies {
			depName, ok := refToName[dep]
			if !ok {
				slog.Warn("unresolved dependency BOMRef", "dep", dep)
				continue
			}
			deps = append(deps, depName)
		}

		dependency[refName] = deps
	}

	return dependency
}

func getCdxComponentInfo(input *[]cdx.Component, files []byte, filename string) map[string]Component {
	componentInfo := make(map[string]Component)

	path, err := file.CopyAndCreate(file.FileInput{
		IsCDX: true,
		Data:  files,
	})
	if err != nil {
		slog.Error("failed to copy and create file", "error", err)
		return nil
	}

	defer func() {
		if err := file.Delete(path); err != nil {
			slog.Error("failed to delete file", "error", err, "filename", filename, "path", path)
		}
	}()

	vulnPkgs, err := file.GetScanResult(path)
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		slog.Error("failed to get scan result", "error", err)
	}

	trimmedVulnPkgs := trimPublicationPrefix(vulnPkgs)

	if input != nil {
		for _, c := range *input {
			componentInfo[c.Name] = Component{
				Name:       c.Name,
				Version:    c.Version,
				VulnNumber: getVulnNumber(c.Name, trimmedVulnPkgs),
				Vulns:      getVulns(c.Name, c.Version, trimmedVulnPkgs),
				Licences:   getCdxLicences(c.Licenses),
			}
		}
	}

	var cves []string
	for _, c := range componentInfo {
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

	for name, info := range componentInfo {
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
			componentInfo[name] = info
		}
	}

	return componentInfo
}

func getCdxLicences(input *cdx.Licenses) string {
	var licences strings.Builder

	if input == nil {
		return ""
	}

	for _, l := range *input {
		if l.License == nil {
			continue
		}

		if licences.Len() > 0 {
			licences.WriteString(", ")
		}

		if l.License.ID != "" {
			licences.WriteString(l.License.ID)
		} else if l.License.Name != "" {
			licences.WriteString(l.License.Name)
		}
	}

	return licences.String()
}
