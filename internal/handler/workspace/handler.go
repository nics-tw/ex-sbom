// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package workspace

import (
	"ex-sbom/internal/domain"
	"ex-sbom/internal/handler/middleware"
	wsvc "ex-sbom/internal/service/workspace"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler holds workspace-related HTTP handlers.
type Handler struct {
	svc *wsvc.Service
}

// New creates a new workspace Handler.
func New(svc *wsvc.Service) *Handler {
	return &Handler{svc: svc}
}

// List returns all workspaces.
// GET /workspaces
func (h *Handler) List(c *gin.Context) {
	workspaces, err := h.svc.List()
	if err != nil {
		slog.Error("ListWorkspaces failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"workspaces": workspaces,
	}})
}

// Create creates a new (empty) workspace in DB.
// POST /workspaces  body: {"name": "<workspace>"}
func (h *Handler) Create(c *gin.Context) {
	var body struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}

	workspaceID, err := h.svc.Create(body.Name)
	if err != nil {
		slog.Error("Failed to create workspace", "name", body.Name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": h.load(c, workspaceID)})
}

// Get loads the SBOMs of an existing workspace.
// GET /workspaces/:id
func (h *Handler) Get(c *gin.Context) {
	workspaceID := middleware.GetWorkspaceID(c)
	c.JSON(http.StatusOK, gin.H{"data": h.load(c, workspaceID)})
}

// Update renames a workspace.
// PUT /workspaces/:id  body: {"name": "<new name>"}
func (h *Handler) Update(c *gin.Context) {
	workspaceID := middleware.GetWorkspaceID(c)

	var body struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}

	if err := h.svc.Update(workspaceID, body.Name); err != nil {
		slog.Error("Failed to update workspace", "id", workspaceID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": gin.H{"workspace_id": workspaceID, "name": body.Name}})
}

// Delete soft-deletes a workspace and all its sbom_records.
// DELETE /workspaces/:id
func (h *Handler) Delete(c *gin.Context) {
	workspaceID := middleware.GetWorkspaceID(c)

	if err := h.svc.Delete(workspaceID); err != nil {
		slog.Error("Failed to delete workspace", "id", workspaceID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	slog.Info("Workspace deleted", "id", workspaceID)
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"workspace_id": workspaceID}})
}

// load is a helper that reloads SBOMs from DB for the given workspace and returns the response payload.
func (h *Handler) load(c *gin.Context, workspaceID domain.WorkspaceID) gin.H {
	names, err := h.svc.Load(workspaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return nil
	}

	return gin.H{
		"workspace_id": workspaceID,
		"sboms":        names,
	}
}