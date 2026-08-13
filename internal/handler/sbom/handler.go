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
	"ex-sbom/util"
	"ex-sbom/util/msg"

	"github.com/gin-gonic/gin"
)

// MaxSBOMUploadBytes is the maximum accepted size for an uploaded SBOM file.
// Requests exceeding this limit are rejected with HTTP 413 before parsing.
const MaxSBOMUploadBytes int64 = 50 << 20 // 50 MiB

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
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

	versions := h.sbomSvc.List(projectID)
	if versions == nil {
		versions = []domain.Version{}
	}

	c.JSON(http.StatusOK, gin.H{msg.RespData: versions})
}

// ListVersions returns all stored SBOM versions for a project, newest first.
// GET /projects/:id/versions
func (h *Handler) ListVersions(c *gin.Context) {
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

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
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}
	oldVersion := c.Param("name")

	var body struct {
		Version domain.Version `json:"version"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Version == "" {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "version")})
		return
	}

	if err := h.sbomSvc.Rename(projectID, oldVersion, body.Version); err != nil {
		if errors.Is(err, repository.ErrVersionNotFound) {
			c.JSON(http.StatusNotFound, gin.H{msg.RespErr: msg.ErrSBOMNotFound})
			return
		}
		if errors.Is(err, repository.ErrVersionExists) {
			c.JSON(http.StatusConflict, gin.H{msg.RespErr: fmt.Sprintf("版本「%s」已存在", body.Version)})
			return
		}

		slog.Error("Failed to rename SBOM version", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	slog.Info("SBOM version renamed", "from", util.LogSafe(oldVersion), "to", util.LogSafe(body.Version))
	c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok", msg.RespData: gin.H{"version": body.Version}})
}

// Delete removes an SBOM version and reloads the project.
// DELETE /projects/:id/sboms/:name
func (h *Handler) Delete(c *gin.Context) {
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

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
		slog.Error("Failed to delete SBOM", "version", util.LogSafe(version), "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	versions, corrupted, err := h.projectSvc.Load(projectID)
	if err != nil {
		slog.Error("Failed to reload project", "projectID", projectID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	slog.Info("SBOM deleted successfully", "version", util.LogSafe(version))
	data := gin.H{
		"project_id": projectID,
		"sboms":      versions,
	}
	if len(corrupted) > 0 {
		data["corrupted"] = corrupted
	}

	c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok", msg.RespData: data})
}

// Diff compares two uploaded SBOMs and returns added/removed/changed components.
// GET /projects/:id/diff?a=<sbom name>&b=<sbom name>
func (h *Handler) Diff(c *gin.Context) {
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

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
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

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
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

	// Cap the request body so an oversized upload is rejected before it is
	// buffered into memory; MaxBytesReader takes effect during FormFile parsing.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxSBOMUploadBytes)

	file, fileHeader, err := c.Request.FormFile("file")
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{msg.RespErr: msg.ErrFileTooLarge})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrBindingJSON})
		return
	}
	defer file.Close()

	baseName := fileHeader.Filename
	if idx := strings.LastIndex(baseName, "."); idx > 0 {
		baseName = baseName[:idx]
	}

	sbomData, err := io.ReadAll(io.LimitReader(file, MaxSBOMUploadBytes+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrBindingJSON})
		return
	}
	if int64(len(sbomData)) > MaxSBOMUploadBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{msg.RespErr: msg.ErrFileTooLarge})
		return
	}

	bomResult, sha256Hash, bomTimestamp, err := h.sbomSvc.Preview(sbomData)
	if err != nil {
		switch {
		case errors.Is(err, ssbom.ErrXMLNotSupported):
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrXMLNotSupport})
		case errors.Is(err, ssbom.ErrInvalidFileType):
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrFileTypeNotSupport})
		case errors.Is(err, ssbom.ErrInvalidSBOMFormat):
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrInvalidSBOM})
		case errors.Is(err, ssbom.ErrSPDXParseFailed):
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf("%s: %s", msg.ErrParsingSPDX, errCause(err))})
		case errors.Is(err, ssbom.ErrCycloneDXParseFailed):
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf("%s: %s", msg.ErrParsingCycloneDX, errCause(err))})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		}

		return
	}

	existingVersion, err := h.sbomSvc.FindVersionBySHA256(projectID, sha256Hash)
	if err != nil {
		slog.Error("Failed to check duplicate SHA-256", "error", err)
		existingVersion = ""
	}

	c.JSON(http.StatusOK, gin.H{msg.RespData: gin.H{
		"bom_result":       bomResult,
		"sha256":           sha256Hash,
		"bom_timestamp":    bomTimestamp,
		"filename":         baseName,
		"existing_version": existingVersion,
		"summary": gin.H{
			"component_count": len(bomResult.Components),
			"vuln_count":      countVulns(bomResult),
		},
	}})
}

// Create saves a pre-parsed SBOM result to DB under the given version name.
// POST /projects/:id/sboms
func (h *Handler) Create(c *gin.Context) {
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

	var body struct {
		Version      domain.Version      `json:"version"`
		BomResult    ssbom.FormattedSBOM `json:"bom_result"`
		SHA256       domain.SHA256       `json:"sha256"`
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

	if err := h.sbomSvc.SaveParsed(projectID, body.Version, body.BomResult, body.SHA256, body.BomTimestamp); err != nil {
		var dupErr *ssbom.DuplicateSHA256Error
		if errors.As(err, &dupErr) {
			c.JSON(http.StatusConflict, gin.H{msg.RespErr: fmt.Sprintf("相同檔案已存在，版本：%s", dupErr.Version)})
			return
		}

		if errors.Is(err, repository.ErrVersionExists) {
			c.JSON(http.StatusConflict, gin.H{msg.RespErr: fmt.Sprintf("版本「%s」已存在", body.Version)})
			return
		}

		if errors.Is(err, ssbom.ErrSHA256Mismatch) {
			c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: msg.ErrSBOMChecksumMismatch})
			return
		}

		slog.Error("Failed to save SBOM", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	names, corrupted, err := h.projectSvc.Load(projectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	slog.Info("SBOM version created", "version", util.LogSafe(body.Version))
	c.JSON(http.StatusOK, toCreateResponse(projectID, names, corrupted))
}

func countVulns(bom ssbom.FormattedSBOM) int {
	count := 0
	for _, info := range bom.ComponentInfo {
		count += info.VulnNumber
	}

	return count
}

func toCreateResponse(projectID domain.ProjectID, versions, corrupted []domain.Version) gin.H {
	data := gin.H{
		"project_id": projectID,
		"sboms":      versions,
	}
	if len(corrupted) > 0 {
		data["corrupted"] = corrupted
	}

	return gin.H{
		msg.RespMsg:  "ok",
		msg.RespData: data,
	}
}

// errCause returns the message of the innermost wrapped error, so responses can
// surface the concrete parse failure (e.g. "invalid specification version")
// instead of only the sentinel wrapper. Errors are wrapped with two %w verbs
// (fmt.Errorf("%w: %w", sentinel, cause)), which yields a multi-error Unwrap.
func errCause(err error) string {
	if u, ok := err.(interface{ Unwrap() []error }); ok {
		if errs := u.Unwrap(); len(errs) > 0 {
			return errs[len(errs)-1].Error()
		}
	}
	return err.Error()
}
