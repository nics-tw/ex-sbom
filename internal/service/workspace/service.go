// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package workspace

import (
	"encoding/json"
	"ex-sbom/internal/domain"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"
	"log/slog"
)

// Service provides workspace business logic using injected repository and cache.
type Service struct {
	repo  repository.Repository
	cache ssbom.Cache
}

// New creates a new workspace Service.
func New(repo repository.Repository, cache ssbom.Cache) *Service {
	return &Service{repo: repo, cache: cache}
}

// Create inserts a new workspace and returns its ID.
func (s *Service) Create(name domain.WorkspaceName) (domain.WorkspaceID, error) {
	return s.repo.CreateWorkspace(name)
}

// List returns all non-deleted workspaces.
func (s *Service) List() ([]domain.WorkspaceInfo, error) {
	return s.repo.GetWorkspaces()
}

// Update renames a workspace.
func (s *Service) Update(id domain.WorkspaceID, name domain.WorkspaceName) error {
	return s.repo.UpdateWorkspaceName(id, name)
}

// Delete soft-deletes the workspace and all its sbom_records, then clears the in-memory cache.
func (s *Service) Delete(id domain.WorkspaceID) error {
	if err := s.repo.SoftDeleteWorkspace(id); err != nil {
		return err
	}
	s.cache.DeleteWorkspace(id)
	return nil
}

// Load fetches the latest SBOMs for a workspace from DB, populates the
// in-memory cache, and returns the list of loaded filenames.
func (s *Service) Load(workspaceID domain.WorkspaceID) ([]domain.Filename, error) {
	records, err := s.repo.GetLatestByWorkspace(workspaceID)
	if err != nil {
		return nil, err
	}

	s.cache.DeleteWorkspace(workspaceID)

	names := make([]domain.Filename, 0, len(records))
	for _, rec := range records {
		var formatted ssbom.FormattedSBOM
		if err := json.Unmarshal(rec.BomResult, &formatted); err != nil {
			slog.Error("Failed to unmarshal SBOM", "filename", rec.Filename, "error", err)
			continue
		}

		s.cache.Set(workspaceID, rec.Filename, formatted)
		names = append(names, rec.Filename)
	}

	return names, nil
}
