// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package report

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"time"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/handler/middleware"
	"ex-sbom/internal/service/pdf"
	ssbom "ex-sbom/internal/service/sbom"
	"ex-sbom/util/msg"

	"github.com/gin-gonic/gin"
)

// Handler holds report-related HTTP handlers.
type Handler struct {
	svc *ssbom.Service
}

func New(svc *ssbom.Service) *Handler {
	return &Handler{svc: svc}
}

// CreatePDF generates a PDF for one project and version.
// GET /projects/:id/sboms/:name/report
func (h *Handler) CreatePDF(c *gin.Context) {
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}
	version := c.Param("name")
	project, bom, err := h.svc.GetReportSnapshot(projectID, version)
	if err != nil {
		if errors.Is(err, domain.ErrVersionNotFound) || errors.Is(err, domain.ErrProjectNotFound) {
			c.JSON(http.StatusNotFound, gin.H{msg.RespErr: err.Error()})
			return
		}
		slog.Error("Failed to load SBOM report", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: "failed to load SBOM report"})
		return
	}

	language := pdf.Language(c.Query("lang"))
	createdAt := time.Now().UTC()
	report := pdf.Report{
		Project: project, Version: version, GeneratedAt: createdAt,
		Language: language, SBOM: bom,
	}
	var body bytes.Buffer
	if err := pdf.GenerateContext(c.Request.Context(), &body, report); err != nil {
		if c.Request.Context().Err() != nil {
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			c.JSON(http.StatusServiceUnavailable, gin.H{msg.RespErr: "PDF rendering timed out"})
			return
		}
		slog.Error("Failed to create PDF report", "error", err)
		response := gin.H{msg.RespErr: "failed to create PDF"}
		if errors.Is(err, pdf.ErrCacheUnavailable) {
			response["code"] = "pdf_cache_unavailable"
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	filename := pdf.FileName(version, createdAt)
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": filename})
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Disposition", disposition)
	c.Header("Content-Language", language)
	c.Data(http.StatusOK, "application/pdf", body.Bytes())
}
