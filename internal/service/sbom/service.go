// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"errors"
	"fmt"
	"time"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/repository"
)

// DuplicateSHA256Error is returned by SaveParsed when the SHA-256 already exists for the project.
type DuplicateSHA256Error struct {
	Version domain.Version
}

func (e *DuplicateSHA256Error) Error() string {
	return fmt.Sprintf("sha256 already exists for version %q", e.Version)
}

// ErrSHA256Mismatch is returned by SaveParsed when the submitted sha256 does
// not match the hash recomputed from the submitted bom_result, meaning the
// pair does not come from the same preview response.
var ErrSHA256Mismatch = errors.New("sha256 does not match bom_result")

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
	unlock := s.cache.LockProject(projectID)
	defer unlock()

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
	unlock := s.cache.LockProject(projectID)
	defer unlock()

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

// FindVersionBySHA256 returns the version name that already has the given SHA-256, or "" if none.
func (s *Service) FindVersionBySHA256(projectID domain.ProjectID, checksum string) (domain.Version, error) {
	version, err := s.repo.FindVersionBySHA256(projectID, checksum)
	if errors.Is(err, repository.ErrVersionNotFound) {
		return "", nil
	}
	return version, err
}

// ListVersions returns all non-deleted SBOM versions for a project, newest first.
func (s *Service) ListVersions(projectID domain.ProjectID) ([]domain.VersionInfo, error) {
	return s.repo.GetAllVersions(projectID)
}

// SaveParsed stores a pre-parsed SBOM result into DB and cache without re-parsing the file.
// Returns *DuplicateSHA256Error if the same SHA-256 already exists for the project.
func (s *Service) SaveParsed(projectID domain.ProjectID, version domain.Version, bom FormattedSBOM, sha256Hash string, bomTimestamp time.Time) error {
	unlock := s.cache.LockProject(projectID)
	defer unlock()

	existing, err := s.repo.FindVersionBySHA256(projectID, sha256Hash)
	if err != nil && !errors.Is(err, repository.ErrVersionNotFound) {
		return err
	}
	if err == nil {
		return &DuplicateSHA256Error{Version: existing}
	}

	sortFormattedSBOM(&bom)

	// The client echoes back the preview payload; recompute the hash so a
	// stale or mismatched bom_result/sha256 pair (e.g. mixed-up requests)
	// is rejected instead of persisted under the wrong identity.
	if actual := HashSBOM(bom); actual != sha256Hash {
		return ErrSHA256Mismatch
	}

	if err := s.repo.CreateSBOM(projectID, version, bom, bomTimestamp, sha256Hash); err != nil {
		return err
	}

	s.cache.Set(projectID, version, bom)

	return nil
}
