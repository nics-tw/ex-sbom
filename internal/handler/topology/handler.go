// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package topology

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"ex-sbom/internal/handler/middleware"
	ssbom "ex-sbom/internal/service/sbom"
	"ex-sbom/util/msg"

	"github.com/gin-gonic/gin"
)

// Handler holds topology-related HTTP handlers.
type Handler struct {
	svc *ssbom.Service
}

// New creates a new topology Handler.
func New(svc *ssbom.Service) *Handler {
	return &Handler{svc: svc}
}

type levelInfo struct {
	Level                 int      `json:"level"`
	Components            []string `json:"components"`
	ComponentsWithVuln    []string `json:"components_with_vuln"`
	ComponentsWithVulnDep []string `json:"components_with_vuln_dep"`
	TotalComponents       int      `json:"total_components"`
	TotalVulns            int      `json:"total_vulns"`
}

type relation struct {
	RootComponent string `json:"root_component"`
	RootLevel     int    `json:"root_level"`
	SubComponent  string `json:"sub_component"`
	SubLevel      int    `json:"sub_level"`
}

// ListComponents returns components grouped by dependency depth.
// GET /projects/:id/sboms/:name/topology
func (h *Handler) ListComponents(c *gin.Context) {
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

	bom, err := h.svc.Get(projectID, c.Param("name"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: msg.ErrSBOMNotFound})
		return
	}

	var levels []levelInfo
	for level, components := range bom.DependencyLevel {
		var totalVulns int
		var withVuln, withVulnDep []string
		for _, comp := range components {
			if info, ok := bom.ComponentInfo[comp]; ok {
				totalVulns += info.VulnNumber
				if info.VulnNumber > 0 {
					withVuln = append(withVuln, comp)
				}
				if info.ContainsVulnDep {
					withVulnDep = append(withVulnDep, comp)
				}
			}
		}
		levels = append(levels, levelInfo{
			Level:                 level,
			Components:            components,
			ComponentsWithVuln:    withVuln,
			ComponentsWithVulnDep: withVulnDep,
			TotalComponents:       len(components),
			TotalVulns:            totalVulns,
		})
	}

	c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok", msg.RespData: levels})
}

// GetRelations returns the dependency graph as a flat list of root→sub pairs.
// GET /projects/:id/sboms/:name/topology/relations
func (h *Handler) GetRelations(c *gin.Context) {
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

	bom, err := h.svc.Get(projectID, c.Param("name"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: msg.ErrSBOMNotFound})
		return
	}

	var relations []relation
	for rootComp, subComps := range bom.Dependency {
		rootLevel, ok := bom.ComponentToLevel[rootComp]
		if !ok {
			if !slices.Contains(bom.Components, rootComp) {
				slog.Error("failed to get root level", "component", rootComp)
				continue
			}
			rootLevel = 0
		}
		for _, subComp := range subComps {
			subLevel, ok := bom.ComponentToLevel[subComp]
			if !ok {
				slog.Error("failed to get sub level", "component", subComp)
				continue
			}

			relations = append(relations, relation{
				RootComponent: rootComp,
				RootLevel:     rootLevel,
				SubComponent:  subComp,
				SubLevel:      subLevel,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok", msg.RespData: relations})
}

// GetComponent returns detailed info for a single component.
// GET /projects/:id/sboms/:name/topology/component?component=
func (h *Handler) GetComponent(c *gin.Context) {
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

	comp := c.Query("component")
	if len(comp) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "component")})
		return
	}

	name := c.Param("name")
	bom, err := h.svc.Get(projectID, name)
	if err != nil {
		slog.Error("GetComponent: sbom not found", "name", name)
		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: msg.ErrSBOMNotFound})
		return
	}

	component, ok := bom.ComponentInfo[comp]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: "component not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok", msg.RespData: toComponentResp(component)})
}

// GetComponentVulnDep returns vulnerability dependency paths for a component.
// GET /projects/:id/sboms/:name/topology/component/vuln-dep?component=
func (h *Handler) GetComponentVulnDep(c *gin.Context) {
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

	name := c.Param("name")
	comp := c.Query("component")
	if len(comp) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "component")})
		return
	}

	if len(name) == 0 || len(comp) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrInvalidComponent})
		return
	}

	bom, err := h.svc.Get(projectID, name)
	if err != nil {
		slog.Error("SBOM not found", slog.String("name", name))
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrInvalidComponent})
		return
	}

	if !slices.Contains(bom.Components, comp) {
		slog.Error("Component not found in SBOM", slog.String("name", name), slog.String("component", comp))
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrInvalidComponent})
		return
	}

	vulnComps := bom.GetVulnComponents()
	if len(vulnComps) == 0 {
		c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok"})
		return
	}

	paths := ssbom.GetVulnDepPaths(comp, vulnComps, bom.Dependency)
	if len(paths) == 0 {
		c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok"})
		return
	}

	c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok", msg.RespData: paths})
}

func toComponentResp(c ssbom.Component) map[string]any {
	hasSevere := ssbom.HasSevereVuln(c.Vulns)
	var versions [][]string
	for _, v := range c.Vulns {
		if !hasSevere || ssbom.IsSevereVuln(v) {
			versions = append(versions, v.FixVersions)
		}
	}

	suggest := ssbom.GetSuggestFixVersions(c.Version, versions...)
	return map[string]any{
		"name":                  c.Name,
		"version":               c.Version,
		"vuln_number":           c.VulnNumber,
		"vulns":                 c.Vulns,
		"contain_vuln_dep":      c.ContainsVulnDep,
		"suggested_fix_version": suggest,
		"is_breaking_change":    ssbom.IsBreakingChange(c.Version, suggest),
		"has_severe_vuln":       hasSevere,
		"licences":              c.Licences,
	}
}
