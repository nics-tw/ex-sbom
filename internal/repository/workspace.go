// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package repository

import (
	"errors"
	"fmt"
	"strings"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CreateProject inserts a new project and returns its id.
// Returns domain.ErrDuplicateProjectName if the name is already taken.
func (r *SBOMRepository) CreateProject(name domain.ProjectName) (domain.ProjectID, error) {
	var existing model.ProjectModel
	err := r.db.
		Where("project_name = ?", name).
		First(&existing).Error
	if err == nil {
		return 0, domain.ErrDuplicateProjectName
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, err
	}

	// DuckDB's LastInsertId always returns 0, so use RETURNING to get the new id.
	var id domain.ProjectID
	if err := r.db.Raw(
		"INSERT INTO projects (project_name, uuid) VALUES (?, ?) RETURNING id",
		name, uuid.New().String(),
	).Scan(&id).Error; err != nil {
		if isDuplicateKey(err) {
			return 0, domain.ErrDuplicateProjectName
		}
		return 0, fmt.Errorf("create project: %w", err)
	}

	return id, nil
}

// UpdateProjectName renames a project.
// Returns domain.ErrDuplicateProjectName if another project already uses the name.
func (r *SBOMRepository) UpdateProjectName(id domain.ProjectID, name domain.ProjectName) error {
	var existing model.ProjectModel
	err := r.db.
		Where("project_name = ? AND id <> ?", name, id).
		First(&existing).Error
	if err == nil {
		return domain.ErrDuplicateProjectName
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	if err := r.db.Model(&model.ProjectModel{}).
		Where("id = ?", id).
		Update("project_name", name).Error; err != nil {
		if isDuplicateKey(err) {
			return domain.ErrDuplicateProjectName
		}
		return err
	}
	return nil
}

// isDuplicateKey reports whether err is a DuckDB unique/primary-key constraint
// violation, which is used to detect concurrent create/rename races that slip
// past the application-level pre-check.
func isDuplicateKey(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "duplicate key")
}

// DeleteProject hard-deletes a project and all its sbom_records.
// DuckDB does not support ON DELETE CASCADE, so child rows are removed
// explicitly before the parent. No GORM Transaction wrapper is used
// because the GORM DuckDB driver does not propagate statements reliably
// inside gorm.Transaction — the non-atomic failure mode here is benign
// (children gone, parent remains → retry succeeds).
func (r *SBOMRepository) DeleteProject(id domain.ProjectID) error {
	if err := r.db.Where("project_id = ?", id).Delete(&model.SBOMRecordModel{}).Error; err != nil {
		return fmt.Errorf("delete sbom_records for project %d: %w", id, err)
	}

	if err := r.db.Where("id = ?", id).Delete(&model.ProjectModel{}).Error; err != nil {
		return fmt.Errorf("delete project %d: %w", id, err)
	}

	return nil
}

// GetProjects returns all projects (id + uuid + name).
func (r *SBOMRepository) GetProjects() ([]domain.ProjectInfo, error) {
	var rows []model.ProjectModel
	if err := r.db.
		Order("created_at ASC").
		Find(&rows).Error; err != nil {

		return nil, err
	}

	projects := make([]domain.ProjectInfo, 0, len(rows))
	for _, w := range rows {
		projects = append(projects, domain.ProjectInfo{ID: w.ID, UUID: w.UUID, Name: w.ProjectName})
	}

	return projects, nil
}
