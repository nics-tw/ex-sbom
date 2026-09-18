// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package project

import (
	"errors"
	"log/slog"
	"net/http"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/handler/middleware"
	psvc "ex-sbom/internal/service/workspace"
	"ex-sbom/util"
	"ex-sbom/util/msg"

	"github.com/gin-gonic/gin"
)

// Handler holds project-related HTTP handlers.
type Handler struct {
	svc *psvc.Service
}

// New creates a new project Handler.
func New(svc *psvc.Service) *Handler {
	return &Handler{svc: svc}
}

// List returns all projects.
// GET /projects
func (h *Handler) List(c *gin.Context) {
	projects, err := h.svc.List()
	if err != nil {
		slog.Error("ListProjects failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{msg.RespData: gin.H{
		"projects": projects,
	}})
}

// Create creates a new (empty) project in DB.
// POST /projects  body: {"name": "<project>"}
func (h *Handler) Create(c *gin.Context) {
	var body struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: "name required"})
		return
	}

	projectID, err := h.svc.Create(body.Name)
	if err != nil {
		if errors.Is(err, domain.ErrDuplicateProjectName) {
			c.JSON(http.StatusConflict, gin.H{msg.RespErr: msg.ErrDuplicateProjectName})
			return
		}
		slog.Error("Failed to create project", "name", util.LogSafe(body.Name), "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	payload, ok := h.load(c, projectID)
	if !ok {
		return
	}

	c.JSON(http.StatusCreated, gin.H{msg.RespData: payload})
}

// Get loads the SBOMs of an existing project.
// GET /projects/:id
func (h *Handler) Get(c *gin.Context) {
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

	payload, ok := h.load(c, projectID)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{msg.RespData: payload})
}

// Update renames a project.
// PUT /projects/:id  body: {"name": "<new name>"}
func (h *Handler) Update(c *gin.Context) {
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: "name required"})
		return
	}

	if err := h.svc.Update(projectID, body.Name); err != nil {
		if errors.Is(err, domain.ErrDuplicateProjectName) {
			c.JSON(http.StatusConflict, gin.H{msg.RespErr: msg.ErrDuplicateProjectName})
			return
		}
		slog.Error("Failed to update project", "id", projectID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{msg.RespData: gin.H{"project_id": projectID, "name": body.Name}})
}

// Delete removes a project and all its sbom_records.
// DELETE /projects/:id
func (h *Handler) Delete(c *gin.Context) {
	projectID, ok := middleware.GetProjectID(c)
	if !ok {
		return
	}

	if err := h.svc.Delete(projectID); err != nil {
		slog.Error("Failed to delete project", "id", projectID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return
	}

	slog.Info("Project deleted", "id", projectID)
	c.JSON(http.StatusOK, gin.H{msg.RespData: gin.H{"project_id": projectID}})
}

// load reloads SBOMs from DB for the given project and returns the payload and success flag.
// On error it writes the error response and returns false — callers must return immediately.
func (h *Handler) load(c *gin.Context, projectID domain.ProjectID) (gin.H, bool) {
	names, corrupted, err := h.svc.Load(projectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{msg.RespErr: err.Error()})
		return nil, false
	}

	payload := gin.H{
		"project_id": projectID,
		"sboms":      names,
	}

	if len(corrupted) > 0 {
		payload["corrupted"] = corrupted
	}

	return payload, true
}
