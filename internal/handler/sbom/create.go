package sbom

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	ssbom "ex-s/internal/service/sbom"
	"ex-s/util/msg"
	"fmt"
	"log/slog"
	"net/http"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gin-gonic/gin"
	sbomreader "github.com/spdx/tools-golang/json"
)

type SBOMType int

const (
	SBOMUnknown SBOMType = iota
	SBOMSPDX
	SBOMCycloneDX
)

type FileType int

const (
	Unknown FileType = iota
	JSON
	XML
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
	param     = "name"
	cyclonedx = "CycloneDX"
)

var (
	SBOMs = make(map[string]SBOM)
)

func toCreateResponse(name string) gin.H {
	return gin.H{
		msg.RespMsg:  "ok",
		msg.RespData: map[string]string{"name": name},
	}
}

// CreateSBOM is the handler that:
// 1. distinguish between the two types of SBOMs, spdx and cyclonedx
// 2. return the SBOM file
// TODO: rethink about the content validation of the SBOM from request
func CreateSBOM(c *gin.Context) {
	sbomData, err := c.GetRawData()
	if err != nil {
		slog.Error("Failed to read request body", "error", err)

		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrBindingJSON})
		return
	}

	switch detectFileType(sbomData) {
	case JSON:
		slog.Info("Detected JSON file type with valid content")
	case XML:
		slog.Info("Detected XML file type with valid content")

		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrXMLNotSupport})
		return
	case Unknown:
		fallthrough
	default:
		slog.Error("Invalid file type", "error", msg.ErrFileTypeNotSupport)
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrFileTypeNotSupport})
		return
	}

	fileName := c.Query("name")
	if len(fileName) == 0 {
		slog.Error("Missing SBOM name", "error", msg.ErrMissingParam)

		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "name")})
		return
	}

	sbomType := detectSBOMFormat(sbomData)

	switch sbomType {
	case SBOMSPDX:
		spdxDoc, err := sbomreader.Read(bytes.NewReader(sbomData))
		if err != nil {
			slog.Error("Failed to parse SPDX SBOM", "error", err)

			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrParsingSPDX})
			return
		}

		if _, ok := SBOMs[fileName]; ok {
			slog.Info("SBOM already exists, overwriting", "name", fileName)
		}

		SBOMs[fileName] = SBOM{
			Name: fileName,
			Type: SBOMSPDX,
			Data: spdxDoc,
		}

		go func() {
			if err := ssbom.ProcessSPDX(fileName, spdxDoc); err != nil {
				slog.Error("Failed to process SPDX SBOM", "error", err)
				return
			}

			slog.Info("process spdx-formatted sbom into shared structs,", "name", fileName)
		}()
	case SBOMCycloneDX:
		decoder := cdx.NewBOMDecoder(bytes.NewReader(sbomData), cdx.BOMFileFormatJSON)

		bom := cdx.BOM{}
		if err := decoder.Decode(&bom); err != nil {
			slog.Error("Failed to parse CycloneDX SBOM", "error", err)

			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrParsingJson})
			return
		}

		if _, ok := SBOMs[fileName]; ok {
			slog.Info("SBOM already exists, overwriting", "name", fileName)
		}

		SBOMs[fileName] = SBOM{
			Name: fileName,
			Type: SBOMCycloneDX,
			Data: bom,
		}

		go func() {
			if err := ssbom.ProcessCDX(fileName, bom); err != nil {
				slog.Error("Failed to process CycloneDX SBOM", "error", err)
				return
			}

			slog.Info("process cyclonedx-formatted sbom into shared structs,", "name", fileName)
		}()
	case SBOMUnknown:
		fallthrough
	default:
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrInvalidSBOM})
		return
	}

	slog.Info("SBOM created", "name", fileName, "type", sbomType)

	c.JSON(http.StatusOK, toCreateResponse(fileName))
}

func detectFileType(data []byte) FileType {
	var js json.RawMessage
	if json.Unmarshal(data, &js) == nil {
		return JSON
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	if _, err := decoder.Token(); err == nil {
		return XML
	}

	return Unknown
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
