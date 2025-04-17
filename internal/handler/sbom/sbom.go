package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"

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
		c.JSON(400, gin.H{"error": "Invalid SBOM data"})
		return
	}

	fileName := c.Query("filename")

	sbomType := detectSBOMFormat(sbomData)

	switch sbomType {
	case SBOMSPDX:
		spdxDoc, err := sbomreader.Read(bytes.NewReader(sbomData))
		if err != nil {
			c.JSON(400, gin.H{"error": "Failed to parse SPDX SBOM"})
			return
		}

		sbom := SBOM{
			Name: fileName,
			Type: SBOMSPDX,
			Data: spdxDoc,
		}

		SBOMs[fileName] = sbom
		c.JSON(200, gin.H{"message": "SPDX SBOM detected", "data": sbom})
	case SBOMCycloneDX:
		// TODO: implement CycloneDX SBOM parsing
	case SBOMUnknown:
		fallthrough
	default:
		c.JSON(400, gin.H{"error": "Unknown SBOM format"})
	}
}

func detectSBOMFormat(data []byte) SBOMType {
	var generic map[string]interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		fmt.Println("Error parsing JSON:", err)
		return SBOMUnknown
	}

	if _, ok := generic["spdxVersion"]; ok {
		if _, ok := generic["SPDXID"]; ok {
			return SBOMSPDX
		}
	}

	if format, ok := generic["bomFormat"]; ok {
		if fmtStr, ok := format.(string); ok && fmtStr == "CycloneDX" {
			return SBOMCycloneDX
		}
	}

	return SBOMUnknown
}
