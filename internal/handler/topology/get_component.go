// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package topology

import (
	ssbom "ex-sbom/internal/service/sbom"
	"ex-sbom/util/msg"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

func toComponentResp(c ssbom.Component) map[string]any {
	HasSevereVuln := ssbom.HasSevereVuln(c.Vulns)
	var versions [][]string

	for _, v := range c.Vulns {
		if !HasSevereVuln || ssbom.IsSevereVuln(v) {
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
		"has_severe_vuln":       HasSevereVuln,
		"licences":              c.Licences,
	}
}

func GetComponent(c *gin.Context) {
	name := c.Query("name")
	if len(name) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "name")})
		return
	}

	comp := c.Query("component")
	if len(comp) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "component")})
		return
	}

	bom, err := ssbom.GetSBOM(name)
	if err != nil {
		slog.Error("GetComponent", "error", err)

		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: msg.ErrSBOMNotFound})
		return
	}

	component, ok := bom.ComponentInfo[comp]
	if !ok {
		slog.Error("GetComponent", "error", fmt.Sprintf("component %s not found in sbom %s", comp, name))

		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: "component not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		msg.RespMsg:  "ok",
		msg.RespData: toComponentResp(component),
	})
}
