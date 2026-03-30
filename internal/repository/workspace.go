// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package repository

import (
	"errors"
	"ex-sbom/internal/domain"
	"ex-sbom/internal/model"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CreateWorkspace inserts a new workspace and returns its id.
// Returns the existing id if the name already exists.
func (r *SBOMRepository) CreateWorkspace(name domain.WorkspaceName) (domain.WorkspaceID, error) {
	var existing model.WorkspaceModel
	err := r.db.
		Where("workspace_name = ? AND deleted_at IS NULL", name).
		First(&existing).Error
	if err == nil {
		return existing.ID, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, err
	}

	// DuckDB's LastInsertId always returns 0, so use RETURNING to get the new id.
	var id domain.WorkspaceID
	if err := r.db.Raw(
		"INSERT INTO workspaces (workspace_name, uuid) VALUES (?, ?) RETURNING id",
		name, uuid.New().String(),
	).Scan(&id).Error; err != nil {
		return 0, fmt.Errorf("create workspace: %w", err)
	}

	return id, nil
}

// UpdateWorkspaceName renames a workspace.
func (r *SBOMRepository) UpdateWorkspaceName(id domain.WorkspaceID, name domain.WorkspaceName) error {
	return r.db.Model(&model.WorkspaceModel{}).
		Where("id = ? AND deleted_at IS NULL", id).
		Update("workspace_name", name).Error
}

// SoftDeleteWorkspace marks a workspace and all its sbom_records as deleted.
func (r *SBOMRepository) SoftDeleteWorkspace(id domain.WorkspaceID) error {
	now := time.Now()
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.SBOMRecordModel{}).
			Where("workspace_id = ? AND deleted_at IS NULL", id).
			Update("deleted_at", now).Error; err != nil {
			return err
		}

		return tx.Model(&model.WorkspaceModel{}).
			Where("id = ? AND deleted_at IS NULL", id).
			Update("deleted_at", now).Error
	})
}

// GetWorkspaces returns all workspaces (id + uuid + name), excluding soft-deleted.
func (r *SBOMRepository) GetWorkspaces() ([]domain.WorkspaceInfo, error) {
	var rows []model.WorkspaceModel
	if err := r.db.
		Where("deleted_at IS NULL").
		Order("created_at ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}

	workspaces := make([]domain.WorkspaceInfo, 0, len(rows))
	for _, w := range rows {
		workspaces = append(workspaces, domain.WorkspaceInfo{ID: w.ID, UUID: w.UUID, Name: w.WorkspaceName})
	}
	return workspaces, nil
}
