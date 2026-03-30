// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package ssbom

import (
	"errors"
	"ex-sbom/internal/domain"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ─── stubRepository ──────────────────────────────────────────────────────────

type stubRepository struct {
	softDeleteSBOMErr error
}

func (r *stubRepository) CreateWorkspace(_ domain.WorkspaceName) (domain.WorkspaceID, error) {
	return 0, nil
}
func (r *stubRepository) UpdateWorkspaceName(_ domain.WorkspaceID, _ domain.WorkspaceName) error {
	return nil
}
func (r *stubRepository) SoftDeleteWorkspace(_ domain.WorkspaceID) error { return nil }
func (r *stubRepository) GetWorkspaces() ([]domain.WorkspaceInfo, error) { return nil, nil }
func (r *stubRepository) Save(_ domain.WorkspaceID, _ domain.Filename, _ any, _ time.Time, _ string) error {
	return nil
}
func (r *stubRepository) SoftDeleteSBOM(_ domain.WorkspaceID, _ domain.Filename) error {
	return r.softDeleteSBOMErr
}
func (r *stubRepository) GetLatestAll() (domain.WorkspaceID, []domain.SBOMEntry, error) {
	return 0, nil, nil
}
func (r *stubRepository) GetLatestByWorkspace(_ domain.WorkspaceID) ([]domain.SBOMEntry, error) {
	return nil, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func newService(repoErr error) (*Service, Cache) {
	repo := &stubRepository{softDeleteSBOMErr: repoErr}
	cache := NewInMemoryCache()
	return NewService(repo, cache), cache
}

const wsID domain.WorkspaceID = 1

// ─── Service.Get ─────────────────────────────────────────────────────────────

func TestService_Get_ReturnsFromCache(t *testing.T) {
	// Arrange
	svc, cache := newService(nil)
	want := FormattedSBOM{Components: []string{"openssl"}}
	cache.Set(wsID, "sbom.json", want)

	// Act
	got, err := svc.Get(wsID, "sbom.json")

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestService_Get_NotFound(t *testing.T) {
	// Arrange
	svc, _ := newService(nil)

	// Act
	_, err := svc.Get(wsID, "missing.json")

	// Assert
	assert.Error(t, err)
}

// ─── Service.List ─────────────────────────────────────────────────────────────

func TestService_List_ReturnsCachedKeys(t *testing.T) {
	// Arrange
	svc, cache := newService(nil)
	cache.Set(wsID, "a.json", FormattedSBOM{})
	cache.Set(wsID, "b.json", FormattedSBOM{})

	// Act
	keys := svc.List(wsID)

	// Assert
	assert.Len(t, keys, 2)
	assert.ElementsMatch(t, []string{"a.json", "b.json"}, keys)
}

func TestService_List_EmptyWorkspace(t *testing.T) {
	// Arrange
	svc, _ := newService(nil)

	// Act
	keys := svc.List(wsID)

	// Assert
	assert.Empty(t, keys)
}

// ─── Service.Delete ───────────────────────────────────────────────────────────

func TestService_Delete_RemovesFromCacheOnSuccess(t *testing.T) {
	// Arrange
	svc, cache := newService(nil)
	cache.Set(wsID, "sbom.json", FormattedSBOM{})

	// Act
	err := svc.Delete(wsID, "sbom.json")

	// Assert
	assert.NoError(t, err)
	_, found := cache.Get(wsID, "sbom.json")
	assert.False(t, found, "SBOM should be removed from cache after delete")
}

func TestService_Delete_ReturnsErrorWhenRepoFails(t *testing.T) {
	// Arrange
	repoErr := errors.New("db error")
	svc, cache := newService(repoErr)
	cache.Set(wsID, "sbom.json", FormattedSBOM{})

	// Act
	err := svc.Delete(wsID, "sbom.json")

	// Assert
	assert.ErrorIs(t, err, repoErr)
	_, stillInCache := cache.Get(wsID, "sbom.json")
	assert.True(t, stillInCache, "cache should be untouched when repo delete fails")
}

// ─── Service.Diff ─────────────────────────────────────────────────────────────

func TestService_Diff_ReturnsResult(t *testing.T) {
	// Arrange
	svc, cache := newService(nil)
	sbomA := FormattedSBOM{
		ComponentInfo:    map[string]Component{"curl": {Version: "7.88.0", VulnNumber: 0}},
		ComponentToLevel: map[string]int{"curl": 1},
	}
	sbomB := FormattedSBOM{
		ComponentInfo:    map[string]Component{"curl": {Version: "7.89.0", VulnNumber: 0}},
		ComponentToLevel: map[string]int{"curl": 1},
	}
	cache.Set(wsID, "a.json", sbomA)
	cache.Set(wsID, "b.json", sbomB)

	// Act
	result, err := svc.Diff(wsID, "a.json", "b.json")

	// Assert
	assert.NoError(t, err)
	assert.NotEmpty(t, result.ByLevel)
}

func TestService_Diff_ErrorWhenFirstSBOMNotFound(t *testing.T) {
	// Arrange
	svc, cache := newService(nil)
	cache.Set(wsID, "b.json", FormattedSBOM{})

	// Act
	_, err := svc.Diff(wsID, "missing.json", "b.json")

	// Assert
	assert.Error(t, err)
}

func TestService_Diff_ErrorWhenSecondSBOMNotFound(t *testing.T) {
	// Arrange
	svc, cache := newService(nil)
	cache.Set(wsID, "a.json", FormattedSBOM{})

	// Act
	_, err := svc.Diff(wsID, "a.json", "missing.json")

	// Assert
	assert.Error(t, err)
}

// ─── Service.Search ───────────────────────────────────────────────────────────

func TestService_Search_DelegatesToCache(t *testing.T) {
	// Arrange
	svc, cache := newService(nil)
	comp := Component{Version: "3.0.1", VulnNumber: 0}
	cache.Set(wsID, "sbom.json", FormattedSBOM{
		ComponentInfo:    map[string]Component{"openssl": comp},
		ComponentToLevel: map[string]int{"openssl": 1},
	})

	// Act
	results := svc.Search(wsID, "openssl")

	// Assert
	assert.Len(t, results, 1)
	assert.Equal(t, "openssl", results[0].Component)
}

func TestService_Search_EmptyQueryReturnsNil(t *testing.T) {
	// Arrange
	svc, cache := newService(nil)
	cache.Set(wsID, "sbom.json", FormattedSBOM{
		ComponentInfo:    map[string]Component{"openssl": {}},
		ComponentToLevel: map[string]int{"openssl": 1},
	})

	// Act
	results := svc.Search(wsID, "")

	// Assert
	assert.Nil(t, results)
}