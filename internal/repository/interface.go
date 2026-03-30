// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package repository

import (
	"ex-sbom/internal/domain"
	"time"
)

// Repository defines the persistence operations for workspaces and SBOMs.
type Repository interface {
	CreateWorkspace(name domain.WorkspaceName) (domain.WorkspaceID, error)
	UpdateWorkspaceName(id domain.WorkspaceID, name domain.WorkspaceName) error
	SoftDeleteWorkspace(id domain.WorkspaceID) error
	GetWorkspaces() ([]domain.WorkspaceInfo, error)
	Save(workspaceID domain.WorkspaceID, filename domain.Filename, bomResult any, bomTimestamp time.Time, md5Hash string) error
	SoftDeleteSBOM(workspaceID domain.WorkspaceID, filename domain.Filename) error
	GetLatestAll() (domain.WorkspaceID, []domain.SBOMEntry, error)
	GetLatestByWorkspace(workspaceID domain.WorkspaceID) ([]domain.SBOMEntry, error)
}