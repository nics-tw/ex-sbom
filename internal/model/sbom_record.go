// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package model

import (
	"time"

	"ex-sbom/internal/domain"
)

// SBOMRecordModel maps to the sbom_records table.
type SBOMRecordModel struct {
	ID              domain.SBOMID        `gorm:"column:id;primaryKey;autoIncrement"`
	ProjectID       domain.ProjectID     `gorm:"column:project_id;not null;index"`
	Version         domain.Version       `gorm:"column:version;not null"`
	BomResultJSON   domain.BomResultJSON `gorm:"column:bom_result_json;type:text"`
	BomResultSHA256 domain.SHA256        `gorm:"column:bom_result_sha256"`
	CreatedAt       time.Time            `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt       *time.Time           `gorm:"column:updated_at;autoUpdateTime"`
	BomTimestamp    *time.Time           `gorm:"column:bom_timestamp"`
}

func (SBOMRecordModel) TableName() string { return "sbom_records" }
