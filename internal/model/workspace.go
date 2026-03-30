// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package model

import "time"

// WorkspaceModel maps to the workspaces table.
type WorkspaceModel struct {
	ID            int64      `gorm:"column:id;primaryKey;autoIncrement"`
	WorkspaceName string     `gorm:"column:workspace_name;uniqueIndex;not null"`
	UUID          string     `gorm:"column:uuid;uniqueIndex"`
	CreatedAt     time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt     *time.Time `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt     *time.Time `gorm:"column:deleted_at;index"`
}

func (WorkspaceModel) TableName() string { return "workspaces" }