package topology

import (
	ssbom "ex-s/internal/service/sbom"
	"ex-s/util/msg"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type (
	levelInfo struct {
		Level              int      `json:"level"`
		Components         []string `json:"components"`
		ComponentsWithVuln []string `json:"components_with_vuln"`
		TotalComponents    int      `json:"total_components"`
		TotalVulns         int      `json:"total_vulns"`
	}
)

func toLevelListResp(bom ssbom.FormattedSBOM) []levelInfo {
	var levels []levelInfo
	for level, components := range bom.DependencyLevel {
		var totalVulns int
		var componentsWithVuln []string

		for _, component := range components {
			info, ok := bom.ComponentInfo[component]
			if ok {
				totalVulns += info.VulnNumber

				if info.VulnNumber > 0 {
					componentsWithVuln = append(componentsWithVuln, component)
				}
			}
		}

		levels = append(levels, levelInfo{
			Level:              level,
			Components:         components,
			ComponentsWithVuln: componentsWithVuln,
			TotalComponents:    len(components),
			TotalVulns:         totalVulns,
		})
	}

	return levels
}

func GetComponentListByLevel(c *gin.Context) {
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

	c.JSON(http.StatusOK, gin.H{
		msg.RespMsg:  "ok",
		msg.RespData: toLevelListResp(bom),
	})
}
