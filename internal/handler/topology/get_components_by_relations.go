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

type (
	relation struct {
		RootComponent string `json:"root_component"`
		RootLevel     int    `json:"root_level"`
		SubComponent  string `json:"sub_component"`
		SubLevel      int    `json:"sub_level"`
	}
)

func toRelationListResp(bom ssbom.FormattedSBOM) []relation {
	var relations []relation

	for rootComponent, subComponents := range bom.Dependency {
		rootLevel, ok := bom.ComponentToLevel[rootComponent]
		if !ok {
			if !slices.Contains(bom.Components, rootComponent) {
				slog.Error("failed to get root level", "component", rootComponent)

				continue
			}

			rootLevel = 0
		}

		for _, subComponent := range subComponents {
			subLevel, ok := bom.ComponentToLevel[subComponent]
			if !ok {
				slog.Error("failed to get sub level", "component", subComponent)

				continue
			}

			relations = append(relations, relation{
				RootComponent: rootComponent,
				RootLevel:     rootLevel,
				SubComponent:  subComponent,
				SubLevel:      subLevel,
			})
		}
	}

	return relations
}

func GetRelations(c *gin.Context) {
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
		msg.RespData: toRelationListResp(bom),
	})
}
