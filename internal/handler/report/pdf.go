// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package report

import (
	"ex-sbom/internal/handler/middleware"
	"ex-sbom/internal/service/pdf"
	ssbom "ex-sbom/internal/service/sbom"
	"ex-sbom/util/msg"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler holds report-related HTTP handlers.
type Handler struct {
	svc *ssbom.Service
}

// New creates a new report Handler.
func New(svc *ssbom.Service) *Handler {
	return &Handler{svc: svc}
}

// CreatePDF generates a PDF report for the given SBOM and sends it as a download.
// GET /workspaces/:id/sboms/:name/report
func (h *Handler) CreatePDF(c *gin.Context) {
	name, bom, err := h.validate(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: err.Error()})
		return
	}

	d := pdf.GetReportData(bom)
	m := pdf.GetMaroto(d)

	doc, err := m.Generate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: "failed to create PDF"})
		return
	}

	filename := pdf.GetFileName(name)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.Data(http.StatusOK, "application/pdf", doc.GetBytes())
}

func (h *Handler) validate(c *gin.Context) (string, ssbom.FormattedSBOM, error) {
	name := c.Param("name")
	if name == "" {
		return "", ssbom.FormattedSBOM{}, fmt.Errorf("sbom name is required")
	}

	workspaceID := middleware.GetWorkspaceID(c)
	bom, err := h.svc.Get(workspaceID, name)
	if err != nil {
		return "", ssbom.FormattedSBOM{}, fmt.Errorf("sbom %s not found", name)
	}

	return name, bom, nil
}
