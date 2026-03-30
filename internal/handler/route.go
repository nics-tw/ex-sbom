// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package handler

import (
	"ex-sbom/internal/handler/middleware"
	reporthandler "ex-sbom/internal/handler/report"
	sbomhandler "ex-sbom/internal/handler/sbom"
	topohandler "ex-sbom/internal/handler/topology"
	wshandler "ex-sbom/internal/handler/workspace"

	"github.com/gin-gonic/gin"
)

func SetupRouterGroup(r *gin.Engine,
	workspaceH *wshandler.Handler,
	sbomH *sbomhandler.Handler,
	topoH *topohandler.Handler,
	reportH *reporthandler.Handler,
) {
	workspaces := r.Group("/workspaces")
	workspaces.GET("", workspaceH.List)
	workspaces.POST("", workspaceH.Create)

	ws := workspaces.Group("/:id")
	ws.Use(middleware.WorkspaceID())
	ws.GET("", workspaceH.Get)
	ws.PUT("", workspaceH.Update)
	ws.DELETE("", workspaceH.Delete)
	ws.GET("/diff", sbomH.Diff)
	ws.GET("/search", sbomH.Search)

	sboms := ws.Group("/sboms")
	sboms.GET("", sbomH.List)
	sboms.POST("", sbomH.Create)

	namedSBOM := sboms.Group("/:name")
	namedSBOM.DELETE("", sbomH.Delete)
	namedSBOM.GET("/report", reportH.CreatePDF)

	topo := namedSBOM.Group("/topology")
	topo.GET("", topoH.ListComponents)
	topo.GET("/relations", topoH.GetRelations)
	topo.GET("/component", topoH.GetComponent)
	topo.GET("/component/vuln-dep", topoH.GetComponentVulnDep)
}
