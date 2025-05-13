package handler

import (
	"ex-s/internal/handler/sbom"
	"ex-s/internal/handler/topology"

	"github.com/gin-gonic/gin"
)

func SetupRouterGroup(r *gin.Engine) {
	sbomGroup := r.Group("/sbom")
	{
		sbomGroup.POST("/upload", sbom.CreateSBOM)
		sbomGroup.DELETE("/delete", sbom.DeleteSBOM)
	}

	topologyGroup := r.Group("/topology")
	{
		topologyGroup.GET("/get_list_by_level", topology.GetComponentListByLevel)
		topologyGroup.GET("/relations", topology.GetRelations)
		topologyGroup.GET("/component", topology.GetComponent)
	}
}
