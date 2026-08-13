// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package psvc

import (
	"encoding/json"
	"log/slog"
	"sync"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"
)

// Service provides project business logic using injected repository and cache.
type Service struct {
	repo  repository.Repository
	cache ssbom.Cache

	// nameMu serializes project create/rename so the check-then-write in the
	// repository is race-free. DuckDB is embedded in this single process, so a
	// process-level lock fully prevents two concurrent requests from writing the
	// same project name.
	nameMu sync.Mutex
}

// New creates a new project Service.
func New(repo repository.Repository, cache ssbom.Cache) *Service {
	return &Service{repo: repo, cache: cache}
}

// Create inserts a new project and returns its ID.
// Returns domain.ErrDuplicateProjectName if the name is already taken.
func (s *Service) Create(name domain.ProjectName) (domain.ProjectID, error) {
	s.nameMu.Lock()
	defer s.nameMu.Unlock()
	return s.repo.CreateProject(name)
}

// List returns all non-deleted projects.
func (s *Service) List() ([]domain.ProjectInfo, error) {
	return s.repo.GetProjects()
}

// Update renames a project.
// Returns domain.ErrDuplicateProjectName if another project already uses the name.
func (s *Service) Update(id domain.ProjectID, name domain.ProjectName) error {
	s.nameMu.Lock()
	defer s.nameMu.Unlock()
	return s.repo.UpdateProjectName(id, name)
}

// Delete removes the project and all its sbom_records, then clears the in-memory cache.
func (s *Service) Delete(id domain.ProjectID) error {
	unlock := s.cache.LockProject(id)
	defer unlock()

	if err := s.repo.DeleteProject(id); err != nil {
		return err
	}
	s.cache.DeleteProject(id)
	return nil
}

// Load fetches the latest SBOMs for a project from DB, populates the
// in-memory cache, and returns the list of loaded filenames plus the versions
// whose persisted JSON failed to decode (degraded state). The cache is only
// rebuilt after every record has been decoded, so a failure mid-way never
// leaves it half-populated.
// The whole read-then-rebuild sequence holds the project lock so a concurrent
// save cannot be overwritten by a stale DB snapshot.
func (s *Service) Load(projectID domain.ProjectID) (names, corrupted []domain.Version, err error) {
	unlock := s.cache.LockProject(projectID)
	defer unlock()

	records, err := s.repo.GetAllByProject(projectID)
	if err != nil {
		return nil, nil, err
	}

	// Decode everything first; the cache stays untouched until the outcome of
	// the whole snapshot is known.
	type loaded struct {
		version domain.Version
		bom     ssbom.FormattedSBOM
	}

	decoded := make([]loaded, 0, len(records))

	for _, rec := range records {
		var formatted ssbom.FormattedSBOM
		if err := json.Unmarshal(rec.BomResult, &formatted); err != nil {
			slog.Error("Corrupted persisted SBOM, excluded from load",
				"projectID", projectID, "version", rec.Version, "error", err)
			corrupted = append(corrupted, rec.Version)
			continue
		}

		decoded = append(decoded, loaded{version: rec.Version, bom: formatted})
	}

	s.cache.DeleteProject(projectID)

	names = make([]domain.Version, 0, len(decoded))
	for _, l := range decoded {
		s.cache.Set(projectID, l.version, l.bom)
		names = append(names, l.version)
	}

	return names, corrupted, nil
}
