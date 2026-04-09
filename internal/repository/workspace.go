// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package repository

import (
	"errors"
	"fmt"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CreateProject inserts a new project and returns its id.
// Returns the existing id if the name already exists.
func (r *SBOMRepository) CreateProject(name domain.ProjectName) (domain.ProjectID, error) {
	var existing model.ProjectModel
	err := r.db.
		Where("project_name = ?", name).
		First(&existing).Error
	if err == nil {
		return existing.ID, nil
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
		return 0, fmt.Errorf("create project: %w", err)
	}

	return id, nil
}

// UpdateProjectName renames a project.
func (r *SBOMRepository) UpdateProjectName(id domain.ProjectID, name domain.ProjectName) error {
	return r.db.Model(&model.ProjectModel{}).
		Where("id = ?", id).
		Update("project_name", name).Error
}

// DeleteProject hard-deletes a project and all its sbom_records.
func (r *SBOMRepository) DeleteProject(id domain.ProjectID) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("project_id = ?", id).Delete(&model.SBOMRecordModel{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).Delete(&model.ProjectModel{}).Error
	})
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
