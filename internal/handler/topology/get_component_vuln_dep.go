package topology

import (
	ssbom "ex-s/internal/service/sbom"
	"ex-s/util/msg"
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

	
}
