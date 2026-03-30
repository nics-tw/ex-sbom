// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"ex-sbom/internal/domain"
	"ex-sbom/internal/repository"
	"fmt"
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
func (s *Service) Get(workspaceID domain.WorkspaceID, name domain.Filename) (FormattedSBOM, error) {
	bom, ok := s.cache.Get(workspaceID, name)
	if !ok {
		return FormattedSBOM{}, fmt.Errorf("SBOM not found: %s", name)
	}
	return bom, nil
}

// List returns the filenames of all SBOMs currently loaded for a workspace.
func (s *Service) List(workspaceID domain.WorkspaceID) []string {
	return s.cache.Keys(workspaceID)
}

// Delete soft-deletes the SBOM record from DB and removes it from the cache.
func (s *Service) Delete(workspaceID domain.WorkspaceID, name domain.Filename) error {
	if err := s.repo.SoftDeleteSBOM(workspaceID, name); err != nil {
		return err
	}
	s.cache.Delete(workspaceID, name)
	return nil
}

// Diff compares two SBOMs in the same workspace and returns the diff.
func (s *Service) Diff(workspaceID domain.WorkspaceID, nameA, nameB string) (DiffResult, error) {
	sbomA, err := s.Get(workspaceID, nameA)
	if err != nil {
		return DiffResult{}, fmt.Errorf("SBOM not found: %s", nameA)
	}

	sbomB, err := s.Get(workspaceID, nameB)
	if err != nil {
		return DiffResult{}, fmt.Errorf("SBOM not found: %s", nameB)
	}

	return DiffSBOMs(sbomA, sbomB), nil
}

// Search returns results matching query across all SBOMs in the workspace.
func (s *Service) Search(workspaceID domain.WorkspaceID, query string) []SearchResult {
	return searchInCache(s.cache.All(workspaceID), query)
}
