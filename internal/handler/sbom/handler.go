// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package sbom

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/handler/middleware"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"
	psvc "ex-sbom/internal/service/workspace"
	"ex-sbom/util/msg"

	"github.com/gin-gonic/gin"
)

// Handler holds SBOM-related HTTP handlers.
type Handler struct {
	sbomSvc    *ssbom.Service
	projectSvc *psvc.Service
}

// New creates a new SBOM Handler.
func New(sbomSvc *ssbom.Service, projectSvc *psvc.Service) *Handler {
	return &Handler{
		sbomSvc:    sbomSvc,
		projectSvc: projectSvc,
	}
}

// List returns the versions of all currently loaded SBOMs for a project.
// GET /projects/:id/sboms
func (h *Handler) List(c *gin.Context) {
	projectID := middleware.GetProjectID(c)
	versions := h.sbomSvc.List(projectID)
	if versions == nil {
		versions = []domain.Version{}
	}

	c.JSON(http.StatusOK, gin.H{msg.RespData: versions})
}

// ListVersions returns all stored SBOM versions for a project, newest first.
// GET /projects/:id/versions
func (h *Handler) ListVersions(c *gin.Context) {
	projectID := middleware.GetProjectID(c)

	versions, err := h.sbomSvc.ListVersions(projectID)
	if err != nil {
		slog.Error("Failed to list versions", "projectID", projectID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	if versions == nil {
		versions = []domain.VersionInfo{}
	}

	c.JSON(http.StatusOK, gin.H{msg.RespData: versions})
}

// Rename updates the version name for an existing SBOM.
// PUT /projects/:id/sboms/:name
func (h *Handler) Rename(c *gin.Context) {
	projectID := middleware.GetProjectID(c)
	oldVersion := c.Param("name")

	var body struct {
		Version domain.Version `json:"version"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Version == "" {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "version")})
		return
	}

	if err := h.sbomSvc.Rename(projectID, oldVersion, body.Version); err != nil {
		if errors.Is(err, repository.ErrVersionExists) {
			c.JSON(http.StatusConflict, gin.H{msg.RespErr: fmt.Sprintf("版本「%s」已存在", body.Version)})
			return
		}

		slog.Error("Failed to rename SBOM version", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	slog.Info("SBOM version renamed", "from", oldVersion, "to", body.Version)
	c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok", msg.RespData: gin.H{"version": body.Version}})
}

// Delete removes an SBOM version and reloads the project.
// DELETE /projects/:id/sboms/:name
func (h *Handler) Delete(c *gin.Context) {
	projectID := middleware.GetProjectID(c)

	version := c.Param("name")
	if len(version) == 0 {
		slog.Error("Missing SBOM version", "error", msg.ErrMissingParam)
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "name")})
		return
	}

	if err := h.sbomSvc.Delete(projectID, version); err != nil {
		if errors.Is(err, repository.ErrVersionNotFound) {
			c.JSON(http.StatusNotFound, gin.H{msg.RespErr: msg.ErrSBOMNotFound})
			return
		}
		slog.Error("Failed to delete SBOM", "version", version, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	versions, err := h.projectSvc.Load(projectID)
	if err != nil {
		slog.Error("Failed to reload project", "projectID", projectID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	slog.Info("SBOM deleted successfully", "version", version)
	c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok", msg.RespData: gin.H{
		"project_id": projectID,
		"sboms":      versions,
	}})
}

// Diff compares two uploaded SBOMs and returns added/removed/changed components.
// GET /projects/:id/diff?a=<sbom name>&b=<sbom name>
func (h *Handler) Diff(c *gin.Context) {
	projectID := middleware.GetProjectID(c)

	nameA := c.Query("a")
	nameB := c.Query("b")
	if nameA == "" || nameB == "" {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: "both 'a' and 'b' query parameters are required"})
		return
	}

	result, err := h.sbomSvc.Diff(projectID, nameA, nameB)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{msg.RespData: result})
}

// Search handles GET /projects/:id/search?q=<query>
func (h *Handler) Search(c *gin.Context) {
	projectID := middleware.GetProjectID(c)

	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: "query parameter 'q' is required"})
		return
	}

	results := h.sbomSvc.Search(projectID, query)
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

// Preview parses an uploaded SBOM file and returns the result without saving to DB.
// POST /projects/:id/sboms/preview
func (h *Handler) Preview(c *gin.Context) {
	file, fileHeader, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrBindingJSON})
		return
	}
	defer file.Close()

	baseName := fileHeader.Filename
	if idx := strings.LastIndex(baseName, "."); idx > 0 {
		baseName = baseName[:idx]
	}

	sbomData, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrBindingJSON})
		return
	}

	bomResult, md5Hash, bomTimestamp, err := h.sbomSvc.Preview(sbomData)
	if err != nil {
		switch {
		case errors.Is(err, ssbom.ErrXMLNotSupported):
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrXMLNotSupport})
		case errors.Is(err, ssbom.ErrInvalidFileType):
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrFileTypeNotSupport})
		case errors.Is(err, ssbom.ErrInvalidSBOMFormat):
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrInvalidSBOM})
		case errors.Is(err, ssbom.ErrSPDXParseFailed):
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrParsingSPDX})
		case errors.Is(err, ssbom.ErrCycloneDXParseFailed):
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrParsingJson})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		}

		return
	}

	c.JSON(http.StatusOK, gin.H{msg.RespData: gin.H{
		"bom_result":    bomResult,
		"md5":           md5Hash,
		"bom_timestamp": bomTimestamp,
		"filename":      baseName,
		"summary": gin.H{
			"component_count": len(bomResult.Components),
			"vuln_count":      countVulns(bomResult),
		},
	}})
}

// Create saves a pre-parsed SBOM result to DB under the given version name.
// POST /projects/:id/sboms
func (h *Handler) Create(c *gin.Context) {
	projectID := middleware.GetProjectID(c)

	var body struct {
		Version      domain.Version      `json:"version"`
		BomResult    ssbom.FormattedSBOM `json:"bom_result"`
		Md5          domain.Md5          `json:"md5"`
		BomTimestamp time.Time           `json:"bom_timestamp"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrBindingJSON})
		return
	}
	if body.Version == "" {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "version")})
		return
	}

	if err := h.sbomSvc.SaveParsed(projectID, body.Version, body.BomResult, body.Md5, body.BomTimestamp); err != nil {
		var dupErr *ssbom.DuplicateMD5Error
		if errors.As(err, &dupErr) {
			c.JSON(http.StatusConflict, gin.H{msg.RespErr: fmt.Sprintf("相同檔案已存在，版本：%s", dupErr.Version)})
			return
		}

		if errors.Is(err, repository.ErrVersionExists) {
			c.JSON(http.StatusConflict, gin.H{msg.RespErr: fmt.Sprintf("版本「%s」已存在", body.Version)})
			return
		}

		slog.Error("Failed to save SBOM", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	names, err := h.projectSvc.Load(projectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	slog.Info("SBOM version created", "version", body.Version)
	c.JSON(http.StatusOK, toCreateResponse(projectID, names))
}

func countVulns(bom ssbom.FormattedSBOM) int {
	count := 0
	for _, info := range bom.ComponentInfo {
		count += info.VulnNumber
	}

	return count
}

func toCreateResponse(projectID domain.ProjectID, versions []domain.Version) gin.H {
	return gin.H{
		msg.RespMsg: "ok",
		msg.RespData: gin.H{
			"project_id": projectID,
			"sboms":      versions,
		},
	}
}
