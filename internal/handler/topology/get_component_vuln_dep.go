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
	"slices"

	"github.com/gin-gonic/gin"
)

func validateExisting(name, comp string) bool {
	if len(name) == 0 || len(comp) == 0 {
		return false
	}

	bom, ok := ssbom.SBOMs[name]
	if !ok {
		slog.Error("SBOM not found", slog.String("name", name))

		return false
	}

	if !slices.Contains(bom.Components, comp) {
		slog.Error("Component not found in SBOM", slog.String("name", name), slog.String("component", comp))

		return false
	}

	return true
}

func toTopoResp(paths []ssbom.VlunDepPath) map[string]interface{} {
	return map[string]interface{}{
		msg.RespMsg:  "ok",
		msg.RespData: paths,
	}
}

// the GetComponentVulnDep API retrieves the vulnerability dependency paths for a specific component in a given SBOM.
func GetComponentVulnDep(c *gin.Context) {
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

	if !validateExisting(name, comp) {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrInvalidComponent})
		return
	}

	vulnComps := ssbom.SBOMs[name].GetVulnComponents()
	if len(vulnComps) == 0 {
		c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok"})
		return
	}

	paths := ssbom.GetVulnDepPaths(comp, vulnComps, ssbom.SBOMs[name].Dependency)
	if len(paths) == 0 {
		c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok"})
		return
	}

	c.JSON(http.StatusOK, toTopoResp(paths))
}
