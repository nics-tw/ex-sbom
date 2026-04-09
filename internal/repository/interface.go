// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package repository

import (
	"time"

	"ex-sbom/internal/domain"
)

// Repository defines the persistence operations for projects and SBOMs.
type Repository interface {
	CreateProject(name domain.ProjectName) (domain.ProjectID, error)
	UpdateProjectName(id domain.ProjectID, name domain.ProjectName) error
	DeleteProject(id domain.ProjectID) error
	GetProjects() ([]domain.ProjectInfo, error)
	CreateSBOM(projectID domain.ProjectID, version domain.Version, result any, timestamp time.Time, checksum string) error
	DeleteSBOM(projectID domain.ProjectID, version domain.Version) error
	RenameVersion(projectID domain.ProjectID, oldVersion, newVersion domain.Version) error
	GetAllVersions(projectID domain.ProjectID) ([]domain.VersionInfo, error)
	GetLatestAll() (domain.ProjectID, []domain.SBOMEntry, error)
	GetLatestByProject(projectID domain.ProjectID) ([]domain.SBOMEntry, error)
}
