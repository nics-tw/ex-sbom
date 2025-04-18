package sbom

import (
	"bytes"
	"encoding/json"
	"ex-s/util/msg"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	sbomreader "github.com/spdx/tools-golang/json"
)

type SBOMType int

const (
	SBOMUnknown SBOMType = iota
	SBOMSPDX
	SBOMCycloneDX
)

type (
	SBOM struct {
		Name string
		Type SBOMType
		Data interface{}
	}
)

const (
	version   = "spdxVersion"
	id        = "SPDXID"
	format    = "bomFormat"
	name      = "name"
	cyclonedx = "CycloneDX"
)

var (
	SBOMs = make(map[string]SBOM)
)

// CreateSBOM is the handler that:
// 1. distinguish between the two types of SBOMs, spdx and cyclonedx
// 2. return the SBOM file
// TODO: rethink about the validation of the SBOM json from request
func CreateSBOM(c *gin.Context) {
	var sbomData []byte
	if err := c.ShouldBindJSON(&sbomData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrInvalidSBOM})
		return
	}

	fileName := c.Query(name)

	sbomType := detectSBOMFormat(sbomData)

	switch sbomType {
	case SBOMSPDX:
		spdxDoc, err := sbomreader.Read(bytes.NewReader(sbomData))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrParsingSPDX})
			return
		}

		sbom := SBOM{
			Name: fileName,
			Type: SBOMSPDX,
			Data: spdxDoc,
		}

		SBOMs[fileName] = sbom
		// TODO: this part should be return SBOM ID
		c.JSON(http.StatusOK, gin.H{msg.RespMsg: "SPDX SBOM detected", msg.RespData: sbom})
	case SBOMCycloneDX:
		// TODO: implement CycloneDX SBOM parsing
	case SBOMUnknown:
		fallthrough
	default:
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrInvalidSBOM})
	}
}

func detectSBOMFormat(data []byte) SBOMType {
	var generic map[string]interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		fmt.Println(msg.ErrParsingJson, err)
		return SBOMUnknown
	}

	if _, ok := generic[version]; ok {
		if _, ok := generic[id]; ok {
			return SBOMSPDX
		}
	}

	if format, ok := generic[format]; ok {
		if fmtStr, ok := format.(string); ok && fmtStr == cyclonedx {
			return SBOMCycloneDX
		}
	}

	return SBOMUnknown
}
