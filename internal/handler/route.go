// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package handler

import (
	"ex-sbom/internal/handler/sbom"
	"ex-sbom/internal/handler/topology"

	"github.com/gin-gonic/gin"
)

func SetupRouterGroup(r *gin.Engine) {
	sbomGroup := r.Group("/sbom")
	{
		sbomGroup.POST("/upload", sbom.CreateSBOM)
		sbomGroup.DELETE("/delete", sbom.DeleteSBOM)
		sbomGroup.GET("/report/:name", sbom.CreateReportPDF)
	}

	topologyGroup := r.Group("/topology")
	{
		topologyGroup.GET("/get_list_by_level", topology.GetComponentListByLevel)
		topologyGroup.GET("/relations", topology.GetRelations)
		topologyGroup.GET("/component", topology.GetComponent)
		topologyGroup.GET("/get_component_vuln_dep", topology.GetComponentVulnDep)
	}
}
