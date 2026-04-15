// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package ssbom

import (
	"errors"
	"testing"
	"time"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/repository"

	"github.com/stretchr/testify/assert"
)

// ─── stubRepository ──────────────────────────────────────────────────────────

type stubRepository struct {
	softDeleteSBOMErr error
	saveErr           error
	renameErr         error
	allVersions       []domain.VersionInfo
}

func (r *stubRepository) CreateProject(_ domain.ProjectName) (domain.ProjectID, error) {
	return 0, nil
}
func (r *stubRepository) UpdateProjectName(_ domain.ProjectID, _ domain.ProjectName) error {
	return nil
}
func (r *stubRepository) DeleteProject(_ domain.ProjectID) error     { return nil }
func (r *stubRepository) GetProjects() ([]domain.ProjectInfo, error) { return nil, nil }
func (r *stubRepository) CreateSBOM(_ domain.ProjectID, _ domain.Version, _ any, _ time.Time, _ string) error {
	return r.saveErr
}
func (r *stubRepository) DeleteSBOM(_ domain.ProjectID, _ domain.Version) error {
	return r.softDeleteSBOMErr
}
func (r *stubRepository) RenameVersion(_ domain.ProjectID, _, _ domain.Version) error {
	return r.renameErr
}
func (r *stubRepository) GetAllVersions(_ domain.ProjectID) ([]domain.VersionInfo, error) {
	return r.allVersions, nil
}
func (r *stubRepository) GetLatestAll() (domain.ProjectID, []domain.SBOMEntry, error) {
	return 0, nil, nil
}
func (r *stubRepository) GetLatestByProject(_ domain.ProjectID) ([]domain.SBOMEntry, error) {
	return nil, nil
}
func (r *stubRepository) FindVersionBySHA256(_ domain.ProjectID, _ domain.SHA256) (domain.Version, error) {
	return "", repository.ErrVersionNotFound
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func newService(repoErr error) (*Service, Cache) {
	repo := &stubRepository{softDeleteSBOMErr: repoErr}
	cache := NewInMemoryCache()
	return NewService(repo, cache), cache
}

func newServiceWithRepo(repo *stubRepository) (*Service, Cache) {
	cache := NewInMemoryCache()
	return NewService(repo, cache), cache
}

const wsID domain.ProjectID = 1

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

// ─── Service.Rename ───────────────────────────────────────────────────────────

func TestService_Rename_UpdatesCacheOnSuccess(t *testing.T) {
	// Arrange
	repo := &stubRepository{}
	svc, cache := newServiceWithRepo(repo)
	want := FormattedSBOM{Components: []string{"zlib"}}
	cache.Set(wsID, "v1", want)

	// Act
	err := svc.Rename(wsID, "v1", "v2")

	// Assert
	assert.NoError(t, err)
	_, oldFound := cache.Get(wsID, "v1")
	assert.False(t, oldFound, "old version should be removed from cache")
	got, newFound := cache.Get(wsID, "v2")
	assert.True(t, newFound, "new version should be in cache")
	assert.Equal(t, want, got)
}

func TestService_Rename_PropagatesRepoError(t *testing.T) {
	// Arrange
	repo := &stubRepository{renameErr: errors.New("duplicate")}
	svc, cache := newServiceWithRepo(repo)
	cache.Set(wsID, "v1", FormattedSBOM{})

	// Act
	err := svc.Rename(wsID, "v1", "v2")

	// Assert
	assert.Error(t, err)
	// Cache should be untouched
	_, stillThere := cache.Get(wsID, "v1")
	assert.True(t, stillThere, "cache should be unchanged when repo rename fails")
	_, newThere := cache.Get(wsID, "v2")
	assert.False(t, newThere, "new key should not appear in cache on failure")
}

func TestService_Rename_SucceedsEvenWhenVersionNotInCache(t *testing.T) {
	// Arrange: repo succeeds, but nothing is in the cache for oldVersion
	repo := &stubRepository{}
	svc, cache := newServiceWithRepo(repo)

	// Act
	err := svc.Rename(wsID, "v1", "v2")

	// Assert
	assert.NoError(t, err)
	_, found := cache.Get(wsID, "v2")
	assert.False(t, found, "no cache entry expected when old version was absent")
}

// ─── Service.SaveParsed ───────────────────────────────────────────────────────

func TestService_SaveParsed_StoresInCacheAndRepo(t *testing.T) {
	// Arrange
	repo := &stubRepository{}
	svc, cache := newServiceWithRepo(repo)
	bom := FormattedSBOM{Components: []string{"curl"}}

	// Act
	err := svc.SaveParsed(wsID, "v1", bom, "abc123", time.Time{})

	// Assert
	assert.NoError(t, err)
	got, found := cache.Get(wsID, "v1")
	assert.True(t, found, "SBOM should be in cache after SaveParsed")
	assert.Equal(t, []string{"curl"}, got.Components)
}

func TestService_SaveParsed_PropagatesRepoError(t *testing.T) {
	// Arrange
	repo := &stubRepository{saveErr: errors.New("version already exists")}
	svc, _ := newServiceWithRepo(repo)
	bom := FormattedSBOM{Components: []string{"curl"}}

	// Act
	err := svc.SaveParsed(wsID, "v1", bom, "abc123", time.Time{})

	// Assert
	assert.Error(t, err)
}

// ─── Service.ListVersions ─────────────────────────────────────────────────────

func TestService_ListVersions_DelegatesToRepo(t *testing.T) {
	// Arrange
	now := time.Now()
	repo := &stubRepository{
		allVersions: []domain.VersionInfo{
			{Version: "v2", CreatedAt: now},
			{Version: "v1", CreatedAt: now.Add(-time.Hour)},
		},
	}
	svc, _ := newServiceWithRepo(repo)

	// Act
	versions, err := svc.ListVersions(wsID)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, versions, 2)
	assert.Equal(t, "v2", versions[0].Version)
	assert.Equal(t, "v1", versions[1].Version)
}
