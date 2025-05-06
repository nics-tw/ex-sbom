package topology

import (
	ssbom "ex-s/internal/service/sbom"
	"ex-s/util/msg"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GetTopology(c *gin.Context) {
	name := c.Query("name")
	if len(name) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "name")})
		return
	}

	bom, err := ssbom.GetSBOM(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: msg.ErrSBOMNotFound})
		return
	}

	// TODO: which level containing component with CVSS score > 7 issue should be implement after the integrate of osv-scanner

	c.JSON(http.StatusOK, gin.H{
		msg.RespMsg:  "ok",
		msg.RespData: bom.DependencyLevel,
	})
}
