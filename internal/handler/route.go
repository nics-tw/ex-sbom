// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package handler

import (
	"ex-sbom/internal/handler/middleware"
	reporthandler "ex-sbom/internal/handler/report"
	sbomhandler "ex-sbom/internal/handler/sbom"
	topohandler "ex-sbom/internal/handler/topology"
	projecthandler "ex-sbom/internal/handler/workspace"

	"github.com/gin-gonic/gin"
)

func SetupRouterGroup(r *gin.Engine,
	projectH *projecthandler.Handler,
	sbomH *sbomhandler.Handler,
	topoH *topohandler.Handler,
	reportH *reporthandler.Handler,
) {
	projects := r.Group("/projects")
	projects.GET("", projectH.List)
	projects.POST("", projectH.Create)

	proj := projects.Group("/:id")
	proj.Use(middleware.ProjectID())
	proj.GET("", projectH.Get)
	proj.PUT("", projectH.Update)
	proj.DELETE("", projectH.Delete)
	proj.GET("/versions", sbomH.ListVersions)
	proj.GET("/diff", sbomH.Diff)
	proj.GET("/search", sbomH.Search)

	sboms := proj.Group("/sboms")
	sboms.GET("", sbomH.List)
	sboms.POST("", sbomH.Create)
	sboms.POST("/preview", sbomH.Preview)

	namedSBOM := sboms.Group("/:name")
	namedSBOM.DELETE("", sbomH.Delete)
	namedSBOM.PUT("", sbomH.Rename)
	namedSBOM.GET("/report", reportH.CreatePDF)

	topo := namedSBOM.Group("/topology")
	topo.GET("", topoH.ListComponents)
	topo.GET("/relations", topoH.GetRelations)
	topo.GET("/component", topoH.GetComponent)
	topo.GET("/component/vuln-dep", topoH.GetComponentVulnDep)
}
