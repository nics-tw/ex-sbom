// SPDX-License-Identifier: MIT

// Package perf defines deterministic processed SBOMs for the performance suite.
package perf

import (
	"fmt"

	ssbom "ex-sbom/internal/service/sbom"
)

type Shape struct {
	Projects   int `json:"projects"`
	Versions   int `json:"versions_per_project"`
	Components int `json:"components_per_version"`
	Fanout     int `json:"max_edges_per_component"`
}

const SearchTerm = "fixture-hit"

func Version(index int) string {
	return fmt.Sprintf("version-%06d", index)
}

// BOM models versions with stable component names, version changes and
// synthetic results. Edges only join consecutive dependency levels.
func BOM(project, version int, shape Shape) ssbom.FormattedSBOM {
	bom := ssbom.FormattedSBOM{
		Components:       make([]string, shape.Components),
		DependencyLevel:  make(map[int][]string),
		Dependency:       make(map[string][]string),
		ComponentToLevel: make(map[string]int, shape.Components),
		ComponentInfo:    make(map[string]ssbom.Component, shape.Components),
	}
	for i := range bom.Components {
		prefix := "fixture-lib"
		if i%10 == 0 {
			prefix = SearchTerm
		}
		name := fmt.Sprintf("%s-%06d-%08d", prefix, project, i)
		bom.Components[i] = name
		level := i % 8
		bom.DependencyLevel[level] = append(bom.DependencyLevel[level], name)
		bom.ComponentToLevel[name] = level
		revision := 0
		if i%5 == 0 {
			revision = version
		}
		component := ssbom.Component{Name: name, Version: fmt.Sprintf("1.0.%d", revision), Licences: "MIT"}
		if i%20 == 0 {
			component.Vulns = []ssbom.Vuln{{ID: fmt.Sprintf("FIXTURE-%08d", i), Summary: "Synthetic benchmark finding", CVSSScore: "7.0"}}
			component.VulnNumber = len(component.Vulns)
		}
		bom.ComponentInfo[name] = component
	}
	for i, name := range bom.Components {
		if bom.ComponentToLevel[name] == 7 {
			continue
		}
		for edge := 0; edge < shape.Fanout; edge++ {
			target := i + 1 + edge*8
			if target >= len(bom.Components) {
				break
			}
			bom.Dependency[name] = append(bom.Dependency[name], bom.Components[target])
		}
	}
	return bom
}
