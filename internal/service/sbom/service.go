// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"fmt"
	"time"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/repository"
)

// Service provides SBOM business logic using injected repository and cache.
type Service struct {
	repo  repository.Repository
	cache Cache
}

// NewService creates a new Service with the given repository and cache.
func NewService(repo repository.Repository, cache Cache) *Service {
	return &Service{repo: repo, cache: cache}
}

// Get retrieves a FormattedSBOM from the cache.
func (s *Service) Get(projectID domain.ProjectID, name domain.Version) (FormattedSBOM, error) {
	bom, ok := s.cache.Get(projectID, name)
	if !ok {
		return FormattedSBOM{}, fmt.Errorf("SBOM not found: %s", name)
	}

	return bom, nil
}

// List returns the filenames of all SBOMs currently loaded for a project.
func (s *Service) List(projectID domain.ProjectID) []domain.Version {
	return s.cache.Keys(projectID)
}

// Rename updates the version name in DB and cache.
func (s *Service) Rename(projectID domain.ProjectID, oldVersion, newVersion domain.Version) error {
	if err := s.repo.RenameVersion(projectID, oldVersion, newVersion); err != nil {
		return err
	}

	if bom, ok := s.cache.Get(projectID, oldVersion); ok {
		s.cache.Delete(projectID, oldVersion)
		s.cache.Set(projectID, newVersion, bom)
	}

	return nil
}

// Delete removes the SBOM record from DB and cache.
func (s *Service) Delete(projectID domain.ProjectID, name domain.Version) error {
	if err := s.repo.DeleteSBOM(projectID, name); err != nil {
		return err
	}

	s.cache.Delete(projectID, name)
	return nil
}

// Diff compares two SBOMs in the same project and returns the diff.
func (s *Service) Diff(projectID domain.ProjectID, nameA, nameB string) (DiffResult, error) {
	sbomA, err := s.Get(projectID, nameA)
	if err != nil {
		return DiffResult{}, fmt.Errorf("SBOM not found: %s", nameA)
	}

	sbomB, err := s.Get(projectID, nameB)
	if err != nil {
		return DiffResult{}, fmt.Errorf("SBOM not found: %s", nameB)
	}

	return DiffSBOMs(sbomA, sbomB), nil
}

// Search returns results matching query across all SBOMs in the project.
func (s *Service) Search(projectID domain.ProjectID, query string) []SearchResult {
	return searchInCache(s.cache.All(projectID), query)
}

// ListVersions returns all non-deleted SBOM versions for a project, newest first.
func (s *Service) ListVersions(projectID domain.ProjectID) ([]domain.VersionInfo, error) {
	return s.repo.GetAllVersions(projectID)
}

// SaveParsed stores a pre-parsed SBOM result into DB and cache without re-parsing the file.
func (s *Service) SaveParsed(projectID domain.ProjectID, version domain.Version, bom FormattedSBOM, md5Hash string, bomTimestamp time.Time) error {
	sortFormattedSBOM(&bom)
	if err := s.repo.CreateSBOM(projectID, version, bom, bomTimestamp, md5Hash); err != nil {
		return err
	}

	s.cache.Set(projectID, version, bom)

	return nil
}
