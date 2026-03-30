// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package model

import "time"

// SBOMRecordModel maps to the sbom_records table.
type SBOMRecordModel struct {
	ID            int64      `gorm:"column:id;primaryKey;autoIncrement"`
	WorkspaceID   int64      `gorm:"column:workspace_id;not null;index"`
	Filename      string     `gorm:"column:filename;not null"`
	BomResultJSON string     `gorm:"column:bom_result_json;type:text"`
	BomResultMd5  string     `gorm:"column:bom_result_md5"`
	CreatedAt     time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt     *time.Time `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt     *time.Time `gorm:"column:deleted_at;index"`
	BomTimestamp  *time.Time `gorm:"column:bom_timestamp"`
}

func (SBOMRecordModel) TableName() string { return "sbom_records" }