package sbom

import (
	ssbom "ex-s/internal/service/sbom"
	"ex-s/util/msg"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

func DeleteSBOM(c *gin.Context) {
	name := c.Query("name")
	if len(name) == 0 {
		slog.Error("Missing SBOM name", "error", msg.ErrMissingParam)

		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "name")})
		return
	}

	if _, exists := SBOMs[name]; !exists {
		slog.Error("SBOM not found", "name", name)

		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: msg.ErrSBOMNotFound})
		return
	}

	delete(SBOMs, name)
	ssbom.DeleteSBOM(name)

	slog.Info("SBOM deleted successfully", "name", name)

	c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok"})
}
