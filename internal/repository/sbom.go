// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package repository

import (
	"encoding/json"
	"errors"
	"ex-sbom/internal/domain"
	"ex-sbom/internal/model"
	"time"

	"gorm.io/gorm"
)

// Save inserts a processed SBOM result into the sbom_records table.
func (r *SBOMRepository) Save(workspaceID domain.WorkspaceID, filename domain.Filename, bomResult any, bomTimestamp time.Time, md5Hash string) error {
	resultJSON, err := json.Marshal(bomResult)
	if err != nil {
		return err
	}

	return r.db.Exec(`
		INSERT INTO sbom_records (workspace_id, filename, bom_result_json, bom_result_md5, bom_timestamp)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (workspace_id, filename, bom_result_md5) DO NOTHING
	`, workspaceID, filename, string(resultJSON), md5Hash, &bomTimestamp).Error
}

// SoftDeleteSBOM marks all records for the given workspace + filename as deleted.
func (r *SBOMRepository) SoftDeleteSBOM(workspaceID domain.WorkspaceID, filename domain.Filename) error {
	return r.db.Model(&model.SBOMRecordModel{}).
		Where("workspace_id = ? AND filename = ? AND deleted_at IS NULL", workspaceID, filename).
		Update("deleted_at", time.Now()).Error
}

// GetLatestAll returns the workspaceID and most recent bom_result per filename for the first workspace
// (ordered by created_at ASC). Used as the default workspace on startup.
func (r *SBOMRepository) GetLatestAll() (domain.WorkspaceID, []domain.SBOMEntry, error) {
	var workspace model.WorkspaceModel
	err := r.db.
		Where("deleted_at IS NULL").
		Order("created_at ASC").
		First(&workspace).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil, nil
	}

	if err != nil {
		return 0, nil, err
	}

	records, err := r.GetLatestByWorkspace(workspace.ID)
	return workspace.ID, records, err
}

// GetLatestByWorkspace returns the most recent bom_result per filename for the given workspace,
// excluding soft-deleted records.
func (r *SBOMRepository) GetLatestByWorkspace(workspaceID domain.WorkspaceID) ([]domain.SBOMEntry, error) {
	var rows []struct {
		Filename      string
		BomResultJSON string
		BomResultMd5  string
	}

	err := r.db.Raw(`
		SELECT r.filename, CAST(r.bom_result_json AS VARCHAR) AS bom_result_json, r.bom_result_md5
		FROM sbom_records r
		WHERE r.workspace_id = ?
		  AND r.deleted_at IS NULL
		ORDER BY r.created_at ASC
	`, workspaceID).Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	records := make([]domain.SBOMEntry, 0, len(rows))
	for _, row := range rows {
		records = append(records, domain.SBOMEntry{
			Filename:  row.Filename,
			BomResult: json.RawMessage(row.BomResultJSON),
			Md5:       row.BomResultMd5,
		})
	}

	return records, nil
}
