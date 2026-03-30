// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package sbom

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"ex-sbom/internal/handler/middleware"
	ssbom "ex-sbom/internal/service/sbom"
	wsvc "ex-sbom/internal/service/workspace"
	"ex-sbom/util/msg"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gin-gonic/gin"
	sbomreader "github.com/spdx/tools-golang/json"
)

// Handler holds SBOM-related HTTP handlers.
type Handler struct {
	sbomSvc      *ssbom.Service
	workspaceSvc *wsvc.Service
}

// New creates a new SBOM Handler.
func New(sbomSvc *ssbom.Service, workspaceSvc *wsvc.Service) *Handler {
	return &Handler{sbomSvc: sbomSvc, workspaceSvc: workspaceSvc}
}

// List returns the names of all currently loaded SBOMs for a workspace.
// GET /workspaces/:id/sboms
func (h *Handler) List(c *gin.Context) {
	workspaceID := middleware.GetWorkspaceID(c)
	names := h.sbomSvc.List(workspaceID)
	if names == nil {
		names = []string{}
	}

	c.JSON(http.StatusOK, gin.H{msg.RespData: names})
}

// Delete soft-deletes an SBOM and reloads the workspace.
// DELETE /workspaces/:id/sboms/:name
func (h *Handler) Delete(c *gin.Context) {
	workspaceID := middleware.GetWorkspaceID(c)

	name := c.Param("name")
	if len(name) == 0 {
		slog.Error("Missing SBOM name", "error", msg.ErrMissingParam)
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "name")})
		return
	}

	if _, err := h.sbomSvc.Get(workspaceID, name); err != nil {
		slog.Error("SBOM not found", "name", name)
		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: msg.ErrSBOMNotFound})
		return
	}

	if err := h.sbomSvc.Delete(workspaceID, name); err != nil {
		slog.Error("Failed to delete SBOM", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	names, err := h.workspaceSvc.Load(workspaceID)
	if err != nil {
		slog.Error("Failed to reload workspace", "workspaceID", workspaceID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	slog.Info("SBOM deleted successfully", "name", name)
	c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok", msg.RespData: gin.H{
		"workspace_id": workspaceID,
		"sboms":        names,
	}})
}

// Diff compares two uploaded SBOMs and returns added/removed/changed components.
// GET /workspaces/:id/diff?a=<sbom name>&b=<sbom name>
func (h *Handler) Diff(c *gin.Context) {
	workspaceID := middleware.GetWorkspaceID(c)

	nameA := c.Query("a")
	nameB := c.Query("b")
	if nameA == "" || nameB == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "both 'a' and 'b' query parameters are required"})
		return
	}

	result, err := h.sbomSvc.Diff(workspaceID, nameA, nameB)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": result})
}

// Search handles GET /workspaces/:id/search?q=<query>
func (h *Handler) Search(c *gin.Context) {
	workspaceID := middleware.GetWorkspaceID(c)

	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: "query parameter 'q' is required"})
		return
	}

	results := h.sbomSvc.Search(workspaceID, query)
	if results == nil {
		results = []ssbom.SearchResult{}
	}

	c.JSON(http.StatusOK, gin.H{
		msg.RespData: gin.H{
			"query":   query,
			"results": results,
			"total":   len(results),
		},
	})
}

// Create is the handler that:
// 1. distinguishes between SPDX and CycloneDX SBOMs
// 2. processes and stores the SBOM
// POST /workspaces/:id/sboms
func (h *Handler) Create(c *gin.Context) {
	workspaceID := middleware.GetWorkspaceID(c)

	fileName := c.PostForm("name")
	if len(fileName) == 0 {
		slog.Error("Missing SBOM name", "error", msg.ErrMissingParam)
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "name")})
		return
	}

	file, _, err := c.Request.FormFile("file")
	if err != nil {
		slog.Error("Failed to read file from form", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrBindingJSON})
		return
	}
	defer file.Close()

	sbomData, err := io.ReadAll(file)
	if err != nil {
		slog.Error("Failed to read file content", "error", err)
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

	sbomType := detectSBOMFormat(sbomData)

	switch sbomType {
	case SBOMSPDX:
		spdxDoc, err := sbomreader.Read(bytes.NewReader(sbomData))
		if err != nil {
			slog.Error("Failed to parse SPDX SBOM", "error", err)
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrParsingSPDX})
			return
		}

		if err := h.sbomSvc.ProcessSPDX(workspaceID, fileName, spdxDoc, sbomData); err != nil {
			slog.Error("Failed to process SPDX SBOM", "error", err)
		}

		slog.Info("process spdx-formatted sbom into shared structs,", "name", fileName)
	case SBOMCycloneDX:
		decoder := cdx.NewBOMDecoder(bytes.NewReader(sbomData), cdx.BOMFileFormatJSON)

		bom := cdx.BOM{}
		if err := decoder.Decode(&bom); err != nil {
			slog.Error("Failed to parse CycloneDX SBOM", "error", err)
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrParsingJson})
			return
		}

		if err := h.sbomSvc.ProcessCDX(workspaceID, fileName, bom, sbomData); err != nil {
			slog.Error("Failed to process CycloneDX SBOM", "error", err)
			return
		}

		slog.Info("process cyclonedx-formatted sbom into shared structs,", "name", fileName)
	case SBOMUnknown:
		fallthrough
	default:
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrInvalidSBOM})
		return
	}

	slog.Info("SBOM created", "name", fileName, "type", sbomType)

	names, err := h.workspaceSvc.Load(workspaceID)
	if err != nil {
		slog.Error("Failed to reload workspace after create", "workspaceID", workspaceID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	c.JSON(http.StatusOK, toCreateResponse(workspaceID, names))
}

func toCreateResponse(workspaceID int64, names []string) gin.H {
	return gin.H{
		msg.RespMsg: "ok",
		msg.RespData: gin.H{
			"workspace_id": workspaceID,
			"sboms":        names,
		},
	}
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
