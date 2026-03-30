// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"errors"
	"ex-sbom/internal/domain"
	"ex-sbom/internal/service/lev"
	"ex-sbom/util"
	"ex-sbom/util/file"
	"fmt"
	"log/slog"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

func (s *Service) ProcessCDX(workspaceID domain.WorkspaceID, name domain.Filename, bom cdx.BOM, rawData []byte) error {
	if bom.BOMFormat != cdx.BOMFormat {
		return fmt.Errorf("invalid BOM format: %s", bom.BOMFormat)
	}

	c := getCdxComponents(bom.Components)
	refToName := getCdxBomRefToName(bom.Components)
	dependency := getCdxDep(bom.Dependencies, refToName)
	dependencyLevel := getCdxDependencyDepthMap(bom, getCdxBomRef(bom.Components), refToName)

	s.cache.Set(workspaceID, name, FormattedSBOM{
		Components:        c,
		DependencyLevel:   dependencyLevel,
		Dependency:        dependency,
		ReverseDependency: getReverseDep(dependency),
		ComponentToLevel:  getComponentToLevel(dependencyLevel),
		ComponentInfo:     getCdxComponentInfo(bom.Components, rawData, name),
	})

	cached, _ := s.cache.Get(workspaceID, name)

	withVuln := []string{}
	for compName, info := range cached.ComponentInfo {
		if info.VulnNumber > 0 {
			withVuln = append(withVuln, compName)
		}
	}

	affecteds := []string{}
	for _, compName := range withVuln {
		affected := getAffecteds(compName, cached.ReverseDependency)
		if len(affected) > 0 {
			affecteds = append(affecteds, affected...)
		}
	}

	distinct := util.StringSlice(affecteds)

	for _, compName := range distinct {
		current, ok := s.cache.Get(workspaceID, name)
		if !ok {
			slog.Error("failed to get name from refA", "refA", name)
			continue
		}
		componentInfo := current.ComponentInfo[compName]
		componentInfo.ContainsVulnDep = true
		current.ComponentInfo[compName] = componentInfo
		s.cache.Set(workspaceID, name, current)
	}

	final, _ := s.cache.Get(workspaceID, name)

	var bomTimestamp time.Time
	if bom.Metadata != nil && bom.Metadata.Timestamp != "" {
		bomTimestamp, _ = time.Parse(time.RFC3339, bom.Metadata.Timestamp)
	}

	sortFormattedSBOM(&final)
	md5Hash := hashSBOM(final)
	if err := s.repo.Save(workspaceID, name, final, bomTimestamp, md5Hash); err != nil {
		slog.Error("Failed to save SBOM to DB", "error", err)
	}

	slog.Info(
		"Process CycloneDX-formatted SBOM successfully",
		"name", name,
		"numbers of components", len(c),
		"total levels", fmt.Sprintf("%d", len(final.DependencyLevel)),
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

func getCdxDependencyDepthMap(sbom cdx.BOM, allComponents []string, refToName map[string]string) map[int][]string {
	// Create dependency graph and track in-degrees
	graph := make(map[string][]string)
	inDegree := make(map[string]int)
	allNodes := make(map[string]bool)

	// Initialize all components as potential nodes
	for _, ref := range allComponents {
		allNodes[ref] = true

		inDegree[ref] = 0
	}

	// Build the dependency graph
	if sbom.Dependencies != nil && len(*sbom.Dependencies) > 0 {
		for _, d := range *sbom.Dependencies {
			if d.Ref != "" {
				allNodes[d.Ref] = true
			}

			if d.Dependencies != nil && len(*d.Dependencies) > 0 {
				for _, dep := range *d.Dependencies {
					// Add edge: d.Ref -> dep
					graph[d.Ref] = append(graph[d.Ref], dep)
					inDegree[dep]++
					allNodes[dep] = true
				}
			}
		}
	}

	// Find all root nodes (in-degree = 0)
	var roots []string
	for node := range allNodes {
		if inDegree[node] == 0 {
			roots = append(roots, node)
		}
	}

	// BFS to determine level of each node
	levelMap := make(map[string]int)
	visited := make(map[string]bool)
	queue := make([]struct {
		node  string
		level int
	}, 0)

	// Add all roots to initial queue at level 0
	for _, root := range roots {
		queue = append(queue, struct {
			node  string
			level int
		}{root, 0})
		visited[root] = true
	}

	// Process the queue
	for len(queue) > 0 {
		// Dequeue
		current := queue[0]
		queue = queue[1:]

		// Set the level for this node
		levelMap[current.node] = current.level

		// Process all neighbors
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

	// Convert from ref-based level map to name-based result
	result := make(map[int][]string)

	// Process each node by its level
	for node, level := range levelMap {
		name, ok := refToName[node]
		if !ok {
			slog.Error("failed to get name for reference", "ref", node)
			continue
		}

		// Add component name to the appropriate level
		result[level] = append(result[level], name)
	}

	// Handle isolated nodes (not visited in BFS) - place at level 0
	for ref := range allNodes {
		if !visited[ref] {
			name, ok := refToName[ref]
			if !ok {
				slog.Error("failed to get name for isolated reference", "ref", ref)
				continue
			}
			result[0] = append(result[0], name)
		}
	}

	// Remove empty levels and ensure continuous numbering
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

	if input != nil && len(*input) > 0 {
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

	// will call api for get epss and lev
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

	if input != nil && len(*input) > 0 {
		for _, l := range *input {
			if l.License != nil {
				if licences.Len() > 0 {
					licences.WriteString(", ")
				}

				if l.License.ID != "" {
					licences.WriteString(l.License.ID)
				} else if l.License.Name != "" {
					licences.WriteString(l.License.Name)
				}
			}
		}
	}

	return licences.String()
}
