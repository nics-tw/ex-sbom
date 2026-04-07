// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package psvc

import (
	"encoding/json"
	"ex-sbom/internal/domain"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"
	"log/slog"
)

// Service provides project business logic using injected repository and cache.
type Service struct {
	repo  repository.Repository
	cache ssbom.Cache
}

// New creates a new project Service.
func New(repo repository.Repository, cache ssbom.Cache) *Service {
	return &Service{repo: repo, cache: cache}
}

// Create inserts a new project and returns its ID.
func (s *Service) Create(name domain.ProjectName) (domain.ProjectID, error) {
	return s.repo.CreateProject(name)
}

// List returns all non-deleted projects.
func (s *Service) List() ([]domain.ProjectInfo, error) {
	return s.repo.GetProjects()
}

// Update renames a project.
func (s *Service) Update(id domain.ProjectID, name domain.ProjectName) error {
	return s.repo.UpdateProjectName(id, name)
}

// Delete soft-deletes the project and all its sbom_records, then clears the in-memory cache.
func (s *Service) Delete(id domain.ProjectID) error {
	if err := s.repo.SoftDeleteProject(id); err != nil {
		return err
	}
	s.cache.DeleteProject(id)
	return nil
}

// Load fetches the latest SBOMs for a project from DB, populates the
// in-memory cache, and returns the list of loaded filenames.
func (s *Service) Load(projectID domain.ProjectID) ([]domain.Version, error) {
	records, err := s.repo.GetLatestByProject(projectID)
	if err != nil {
		return nil, err
	}

	s.cache.DeleteProject(projectID)

	names := make([]domain.Version, 0, len(records))
	for _, rec := range records {
		var formatted ssbom.FormattedSBOM
		if err := json.Unmarshal(rec.BomResult, &formatted); err != nil {
			slog.Error("Failed to unmarshal SBOM", "version", rec.Version, "error", err)
			continue
		}

		s.cache.Set(projectID, rec.Version, formatted)
		names = append(names, rec.Version)
	}

	return names, nil
}
