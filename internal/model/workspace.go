// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package model

import (
	"time"

	"ex-sbom/internal/domain"
)

// ProjectModel maps to the projects table.
type ProjectModel struct {
	ID          domain.ProjectID   `gorm:"column:id;primaryKey;autoIncrement"`
	ProjectName domain.ProjectName `gorm:"column:project_name;uniqueIndex;not null"`
	UUID        domain.UUID        `gorm:"column:uuid;uniqueIndex"`
	CreatedAt   time.Time          `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt   *time.Time         `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt   *time.Time         `gorm:"column:deleted_at;index"`
}

func (ProjectModel) TableName() string { return "projects" }
