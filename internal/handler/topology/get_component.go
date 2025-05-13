package topology

import (
	ssbom "ex-s/internal/service/sbom"
	"ex-s/util/msg"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func toComponentResp(c ssbom.Component) map[string]any {
	return map[string]any{
		"name":        c.Name,
		"version":     c.Version,
		"vuln_number": c.VulnNumber,
		"vulns":       c.Vulns,
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
		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: msg.ErrSBOMNotFound})
		return
	}

	component, ok := bom.ComponentInfo[comp]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: "component not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		msg.RespMsg:  "ok",
		msg.RespData: toComponentResp(component),
	})
}
