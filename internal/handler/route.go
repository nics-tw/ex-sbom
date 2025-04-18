package handler

import (
	"ex-s/internal/handler/sbom"

	"github.com/gin-gonic/gin"
)

func SetupRouterGroup(r *gin.Engine) {
	// Create a new router group for SBOM-related routes
	sbomGroup := r.Group("/sbom")
	{
		sbomGroup.POST("/create", sbom.CreateSBOM)
		sbomGroup.DELETE("/delete/:name", sbom.DeleteSBOM)
	}
}
