// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package repository

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrVersionExists is returned by CreateSBOM when the (project_id, version) pair already exists.
var ErrVersionExists = errors.New("version already exists")

// ErrVersionNotFound is returned by DeleteSBOM when no matching version exists.
var ErrVersionNotFound = errors.New("version not found")

// CreateSBOM inserts a processed SBOM result into the sbom_records table.
// Returns ErrVersionExists if the same (project_id, version) already exists.
func (r *SBOMRepository) CreateSBOM(projectID domain.ProjectID, version domain.Version, result any, timestamp time.Time, checksum string) error {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return err
	}

	// A zero timestamp (e.g. SPDX without a creation date) must be stored as
	// NULL rather than 0001-01-01, otherwise reports/UI show year 0001 instead
	// of an "unknown" timestamp.
	ts := &timestamp
	if timestamp.IsZero() {
		ts = nil
	}

	record := model.SBOMRecordModel{
		ProjectID:       projectID,
		Version:         version,
		BomResultJSON:   string(resultJSON),
		BomResultSHA256: checksum,
		BomTimestamp:    ts,
	}
	db := r.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&record)
	if db.Error != nil {
		return db.Error
	}
	if db.RowsAffected == 0 {
		return ErrVersionExists
	}

	return nil
}

// RenameVersion updates the version name for a given project + version.
// Returns ErrVersionNotFound if oldVersion does not exist in the project.
// Returns ErrVersionExists if newVersion already exists in the project.
// Uses DELETE + INSERT inside a transaction because DuckDB's ART index
// implementation produces spurious PK violations on plain UPDATE statements.
func (r *SBOMRepository) RenameVersion(projectID domain.ProjectID, oldVersion, newVersion domain.Version) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		// CAST bom_result_json to VARCHAR: DuckDB returns JSON columns as
		// map[string]interface{} which cannot be scanned into a string field.
		var rec model.SBOMRecordModel
		err := tx.
			Select(
				"id, project_id, version",
				"CAST(bom_result_json AS VARCHAR) AS bom_result_json",
				"bom_result_sha256, bom_timestamp, created_at, updated_at",
			).
			Where("project_id = ? AND version = ?", projectID, oldVersion).
			First(&rec).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: %s", ErrVersionNotFound, oldVersion)
			}

			return err
		}

		if err := tx.Delete(&rec).Error; err != nil {
			return err
		}

		rec.ID = 0
		rec.Version = newVersion
		db := tx.
			Clauses(clause.OnConflict{DoNothing: true}).
			Create(&rec)
		if db.Error != nil {
			return db.Error
		}
		if db.RowsAffected == 0 {
			return ErrVersionExists
		}

		return nil
	})
}

// DeleteSBOM hard-deletes the record for the given project + version.
// Returns ErrVersionNotFound if no matching record exists.
func (r *SBOMRepository) DeleteSBOM(projectID domain.ProjectID, version domain.Version) error {
	db := r.db.Where("project_id = ? AND version = ?", projectID, version).Delete(&model.SBOMRecordModel{})
	if db.Error != nil {
		return db.Error
	}
	if db.RowsAffected == 0 {
		return ErrVersionNotFound
	}

	return nil
}

// GetAllVersions returns version name and creation time for all non-deleted records in a project,
// ordered newest first.
func (r *SBOMRepository) GetAllVersions(projectID domain.ProjectID) ([]domain.VersionInfo, error) {
	var rows []domain.VersionInfo
	err := r.db.Model(&model.SBOMRecordModel{}).
		Select("version, created_at").
		Where("project_id = ?", projectID).
		Order("created_at desc").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	return rows, nil
}

// GetLatestAll returns the projectID and most recent bom_result per filename for the first project
// (ordered by created_at ASC). Used as the default project on startup.
func (r *SBOMRepository) GetLatestAll() (domain.ProjectID, []domain.SBOMEntry, error) {
	var project model.ProjectModel
	err := r.db.
		Order("created_at ASC").
		First(&project).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil, nil
	}

	if err != nil {
		return 0, nil, err
	}

	records, err := r.GetAllByProject(project.ID)
	return project.ID, records, err
}

// FindVersionBySHA256 returns the version name for a given project + SHA-256 checksum.
// Returns ErrVersionNotFound if no matching record exists.
func (r *SBOMRepository) FindVersionBySHA256(projectID domain.ProjectID, checksum domain.SHA256) (domain.Version, error) {
	var rows []struct {
		Version domain.Version
	}
	err := r.db.Model(&model.SBOMRecordModel{}).
		Select("version").
		Where("project_id = ? AND bom_result_sha256 = ?", projectID, checksum).
		Limit(1).
		Scan(&rows).Error
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", ErrVersionNotFound
	}

	return rows[0].Version, nil
}

// GetAllByProject returns all stored SBOM entries for the given project,
// ordered by created_at ASC.
func (r *SBOMRepository) GetAllByProject(projectID domain.ProjectID) ([]domain.SBOMEntry, error) {
	var rows []struct {
		Version         domain.Version
		BomResultJSON   domain.BomResultJSON
		BomResultSHA256 domain.SHA256
	}

	err := r.db.Model(&model.SBOMRecordModel{}).
		Select("version, CAST(bom_result_json AS VARCHAR) AS bom_result_json, bom_result_sha256").
		Where("project_id = ?", projectID).
		Order("created_at ASC").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	records := make([]domain.SBOMEntry, 0, len(rows))
	for _, row := range rows {
		records = append(records, domain.SBOMEntry{
			Version:   row.Version,
			BomResult: json.RawMessage(row.BomResultJSON),
			SHA256:    row.BomResultSHA256,
		})
	}

	return records, nil
}
