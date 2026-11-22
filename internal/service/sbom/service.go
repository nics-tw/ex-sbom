// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"encoding/json"
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

// FindVersionForSBOM checks a normalized result against current and historical records.
func (s *Service) FindVersionForSBOM(projectID domain.ProjectID, checksum string, bom FormattedSBOM) (domain.Version, error) {
	legacy := legacyHashSBOM(bom)
	checksums := []string{checksum}
	if legacy != checksum {
		checksums = append(checksums, legacy)
	}
	for _, candidate := range checksums {
		version, err := s.repo.FindVersionBySHA256(projectID, candidate)
		if err == nil {
			return version, nil
		}
		if !errors.Is(err, repository.ErrVersionNotFound) {
			return "", err
		}
	}
	// If no component has multiple findings, the vulnerability sort could not
	// have changed the stored hash and the exact lookups were sufficient.
	for _, component := range bom.ComponentInfo {
		if len(component.Vulns) > 1 {
			return s.findVersionWithOldVulnOrder(projectID, checksum, legacy)
		}
	}
	return "", nil
}

// Old checksums used scanner order. Normalize the persisted result for comparison
// on an exact miss without rewriting existing records.
func (s *Service) findVersionWithOldVulnOrder(projectID domain.ProjectID, checksum, legacy string) (domain.Version, error) {
	records, err := s.repo.GetAllByProject(projectID)
	if err != nil {
		return "", err
	}
	for _, record := range records {
		var stored FormattedSBOM
		if err := json.Unmarshal(record.BomResult, &stored); err != nil {
			continue
		}
		sortFormattedSBOM(&stored)
		// The legacy candidate only matches when the persisted record itself omitted
		// fix versions. A modern record with different fix versions stays distinct.
		if hash := HashSBOM(stored); hash == checksum || hash == legacy {
			return record.Version, nil
		}
	}
	return "", nil
}

// ListVersions returns all non-deleted SBOM versions for a project, newest first.
func (s *Service) ListVersions(projectID domain.ProjectID) ([]domain.VersionInfo, error) {
	return s.repo.GetAllVersions(projectID)
}

// SaveParsed stores a pre-parsed SBOM result into DB and cache without re-parsing the file.
// Returns domain.ErrProjectNotFound if the project does not exist.
// Returns *DuplicateSHA256Error if the same SHA-256 already exists for the project.
func (s *Service) SaveParsed(projectID domain.ProjectID, version domain.Version, bom FormattedSBOM, sha256Hash string, bomTimestamp time.Time) error {
	unlock := s.cache.LockProject(projectID)
	defer unlock()

	// Checked under the project lock (project deletion takes the same lock),
	// so a missing project is reported as such instead of surfacing later as
	// a raw foreign-key violation from the insert.
	exists, err := s.repo.ProjectExists(projectID)
	if err != nil {
		return err
	}
	if !exists {
		return domain.ErrProjectNotFound
	}

	sortFormattedSBOM(&bom)

	// The client echoes back the preview payload; recompute the hash so a
	// stale or mismatched bom_result/sha256 pair (e.g. mixed-up requests)
	// is rejected instead of persisted under the wrong identity.
	if actual := HashSBOM(bom); actual != sha256Hash {
		return ErrSHA256Mismatch
	}

	existing, err := s.FindVersionForSBOM(projectID, sha256Hash, bom)
	if err != nil {
		return err
	}
	if existing != "" {
		return &DuplicateSHA256Error{Version: existing}
	}

	if err := s.repo.CreateSBOM(projectID, version, bom, bomTimestamp, sha256Hash); err != nil {
		return err
	}

	s.cache.Set(projectID, version, bom)

	return nil
}
