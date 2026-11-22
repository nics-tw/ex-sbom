// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package ssbom

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── stubRepository ──────────────────────────────────────────────────────────

type stubRepository struct {
	softDeleteSBOMErr error
	saveErr           error
	renameErr         error
	allVersions       []domain.VersionInfo
	projectMissing    bool
}

func (r *stubRepository) CreateProject(_ domain.ProjectName) (domain.ProjectID, error) {
	return 0, nil
}
func (r *stubRepository) UpdateProjectName(_ domain.ProjectID, _ domain.ProjectName) error {
	return nil
}
func (r *stubRepository) DeleteProject(_ domain.ProjectID) error     { return nil }
func (r *stubRepository) GetProjects() ([]domain.ProjectInfo, error) { return nil, nil }
func (r *stubRepository) ProjectExists(_ domain.ProjectID) (bool, error) {
	return !r.projectMissing, nil
}
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
func (r *stubRepository) GetAllByProject(_ domain.ProjectID) ([]domain.SBOMEntry, error) {
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
	err := svc.SaveParsed(wsID, "v1", bom, HashSBOM(bom), time.Time{})

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
	err := svc.SaveParsed(wsID, "v1", bom, HashSBOM(bom), time.Time{})

	// Assert
	assert.Error(t, err)
}

func TestService_SaveParsed_RejectsChecksumMismatch(t *testing.T) {
	// Arrange: sha256 does not come from the submitted bom_result, e.g. a
	// stale preview payload mixed with another request's checksum
	repo := &stubRepository{}
	svc, cache := newServiceWithRepo(repo)
	bom := FormattedSBOM{Components: []string{"curl"}}

	// Act
	err := svc.SaveParsed(wsID, "v1", bom, "not-the-real-hash", time.Time{})

	// Assert
	assert.ErrorIs(t, err, ErrSHA256Mismatch)
	_, found := cache.Get(wsID, "v1")
	assert.False(t, found, "mismatched payload must not be cached")
}

func TestService_SaveParsed_MissingProjectReturnsNotFound(t *testing.T) {
	// Arrange: the target project does not exist (e.g. deleted in another tab
	// between preview and commit)
	repo := &checksumTrackingRepo{
		stubRepository: stubRepository{projectMissing: true},
		byChecksum:     map[string]domain.Version{},
	}
	cache := NewInMemoryCache()
	svc := NewService(repo, cache)
	bom := FormattedSBOM{Components: []string{"curl"}}

	// Act
	err := svc.SaveParsed(wsID, "v1", bom, HashSBOM(bom), time.Time{})

	// Assert: reported as not-found, and the insert is never attempted (it
	// would otherwise surface as a raw foreign-key violation)
	assert.ErrorIs(t, err, domain.ErrProjectNotFound)
	assert.Equal(t, 0, repo.inserts, "no insert may be attempted for a missing project")
	_, found := cache.Get(wsID, "v1")
	assert.False(t, found, "nothing may be cached for a missing project")
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

// ─── Service.SaveParsed (concurrency) ────────────────────────────────────────

// checksumTrackingRepo simulates the real repository's checksum lookup:
// FindVersionBySHA256 reflects previous CreateSBOM calls. It is intentionally
// unsynchronized — SaveParsed's per-project lock must serialize access, and
// `go test -race` will fail if it does not.
type checksumTrackingRepo struct {
	stubRepository
	byChecksum   map[string]domain.Version
	records      []domain.SBOMEntry
	inserts      int
	historyReads int
	historyErr   error
}

func (r *checksumTrackingRepo) CreateSBOM(_ domain.ProjectID, version domain.Version, _ any, _ time.Time, checksum string) error {
	r.byChecksum[checksum] = version
	r.inserts++
	return nil
}

func (r *checksumTrackingRepo) FindVersionBySHA256(_ domain.ProjectID, checksum domain.SHA256) (domain.Version, error) {
	if v, ok := r.byChecksum[string(checksum)]; ok {
		return v, nil
	}
	return "", repository.ErrVersionNotFound
}

func (r *checksumTrackingRepo) GetAllByProject(projectID domain.ProjectID) ([]domain.SBOMEntry, error) {
	r.historyReads++
	if projectID != wsID {
		return nil, nil
	}
	return r.records, r.historyErr
}

func TestService_SaveParsedDetectsLegacyChecksumDuplicate(t *testing.T) {
	bom := FormattedSBOM{ComponentInfo: map[string]Component{
		"pkg": {Vulns: []Vuln{{ID: "CVE-1", FixVersions: []string{"1.1"}}}},
	}}
	current := HashSBOM(bom)
	legacy := legacyHashSBOM(bom)
	assert.NotEqual(t, current, legacy)

	repo := &checksumTrackingRepo{byChecksum: map[string]domain.Version{legacy: "existing"}}
	svc := NewService(repo, NewInMemoryCache())
	version, err := svc.FindVersionForSBOM(wsID, current, bom)
	assert.NoError(t, err)
	assert.Equal(t, domain.Version("existing"), version)

	err = svc.SaveParsed(wsID, "duplicate", bom, current, time.Time{})
	var duplicate *DuplicateSHA256Error
	assert.ErrorAs(t, err, &duplicate)
	assert.Zero(t, repo.inserts)
}

func TestService_SaveParsedCanonicalizesFindingOrder(t *testing.T) {
	newBOM := func(vulns ...Vuln) FormattedSBOM {
		return FormattedSBOM{ComponentInfo: map[string]Component{
			"pkg": {Vulns: vulns},
		}}
	}
	a := Vuln{ID: "CVE-1", FixVersions: []string{"1.1"}}
	b := Vuln{ID: "CVE-2", FixVersions: []string{"2.1"}}
	unsorted := newBOM(b, a)
	canonical := newBOM(a, b)
	sortFormattedSBOM(&canonical)
	checksum := HashSBOM(canonical)
	require.NotEqual(t, checksum, HashSBOM(unsorted))

	for _, tc := range []struct {
		name      string
		stored    FormattedSBOM
		duplicate bool
	}{
		{"older scanner order", newBOM(b, a), true},
		{"older scanner order without fix versions", newBOM(Vuln{ID: b.ID}, Vuln{ID: a.ID}), true},
		{"different fix versions remain distinct", newBOM(b, Vuln{ID: a.ID, FixVersions: []string{"1.2"}}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storedJSON, err := json.Marshal(tc.stored)
			require.NoError(t, err)
			storedChecksum := HashSBOM(tc.stored)
			repo := &checksumTrackingRepo{
				byChecksum: map[string]domain.Version{storedChecksum: "existing"},
				records:    []domain.SBOMEntry{{Version: "existing", SHA256: storedChecksum, BomResult: storedJSON}},
			}
			svc := NewService(repo, NewInMemoryCache())
			version, err := svc.FindVersionForSBOM(wsID, checksum, canonical)
			require.NoError(t, err)
			err = svc.SaveParsed(wsID, "submitted", newBOM(b, a), checksum, time.Time{})
			if tc.duplicate {
				assert.Equal(t, domain.Version("existing"), version)
				var duplicate *DuplicateSHA256Error
				assert.ErrorAs(t, err, &duplicate)
				assert.Zero(t, repo.inserts)
			} else {
				assert.Empty(t, version)
				assert.NoError(t, err)
				assert.Equal(t, domain.Version("submitted"), repo.byChecksum[checksum])
			}
		})
	}
}

func TestService_SaveParsedCanonicalizesFixVersionOrder(t *testing.T) {
	makeBOM := func(suggest, other string, candidates ...string) FormattedSBOM {
		return FormattedSBOM{ComponentInfo: map[string]Component{
			"pkg": {Vulns: []Vuln{{
				ID: "CVE-1", SuggestFixVersion: suggest, OtherFixVersions: other, FixVersions: candidates,
			}}},
		}}
	}
	const suggest = "1.2-a, 2.0"
	const other = "1.2-b, 3.0"
	canonical := makeBOM(suggest, other, "1.2-a", "1.2-b", "2.0", "3.0")
	sortFormattedSBOM(&canonical)
	checksum := HashSBOM(canonical)
	reordered := makeBOM(suggest, "3.0, 1.2-b", "3.0", "1.2-b", "2.0", "1.2-a")
	changed := makeBOM(suggest, other, "1.2-a", "1.2-b", "2.0", "3.1")

	t.Run("preview checksum binds the candidates", func(t *testing.T) {
		repo := &checksumTrackingRepo{byChecksum: map[string]domain.Version{}}
		svc := NewService(repo, NewInMemoryCache())
		require.ErrorIs(t, svc.SaveParsed(wsID, "changed", changed, checksum, time.Time{}), ErrSHA256Mismatch)
		require.NoError(t, svc.SaveParsed(wsID, "reordered", reordered, checksum, time.Time{}))
		assert.Equal(t, domain.Version("reordered"), repo.byChecksum[checksum])
	})

	for _, tc := range []struct {
		name      string
		stored    FormattedSBOM
		duplicate bool
	}{
		{"stored candidates in scanner order", makeBOM(suggest, "3.0, 1.2-b", "3.0", "2.0", "1.2-b", "1.2-a"), true},
		{"legacy JSON with a different tied suggestion", makeBOM("1.2-b, 2.0", "3.0, 1.2-a"), true},
		{"modern candidate set differs", changed, false},
		{"modern candidate spelling differs", makeBOM(suggest, other, "v1.2-a", "1.2-b", "2.0", "3.0"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storedJSON, err := json.Marshal(tc.stored)
			require.NoError(t, err)
			storedChecksum := HashSBOM(tc.stored)
			require.NotEqual(t, checksum, storedChecksum)
			repo := &checksumTrackingRepo{
				byChecksum: map[string]domain.Version{storedChecksum: "existing"},
				records:    []domain.SBOMEntry{{Version: "existing", SHA256: storedChecksum, BomResult: storedJSON}},
			}
			svc := NewService(repo, NewInMemoryCache())
			version, err := svc.FindVersionForSBOM(wsID, checksum, canonical)
			require.NoError(t, err)
			err = svc.SaveParsed(wsID, "submitted", canonical, checksum, time.Time{})
			if tc.duplicate {
				assert.Equal(t, domain.Version("existing"), version)
				var duplicate *DuplicateSHA256Error
				assert.ErrorAs(t, err, &duplicate)
				assert.Zero(t, repo.inserts)
			} else {
				assert.Empty(t, version)
				assert.NoError(t, err)
				assert.Equal(t, 1, repo.inserts)
			}
		})
	}
}

func TestService_FindVersionForSBOMMatchesLegacyPrefixedTie(t *testing.T) {
	makeBOM := func(suggestion string, candidates []string) FormattedSBOM {
		return FormattedSBOM{ComponentInfo: map[string]Component{
			"pkg": {Vulns: []Vuln{{
				ID: "CVE-1", SuggestFixVersion: suggestion, OtherFixVersions: "v1.2-a, v1.2-b",
				FixVersions: candidates,
			}}},
		}}
	}
	stored := makeBOM("1.2-b", nil)
	storedJSON, err := json.Marshal(stored)
	require.NoError(t, err)
	storedChecksum := HashSBOM(stored)
	repo := &checksumTrackingRepo{
		byChecksum: map[string]domain.Version{storedChecksum: "existing"},
		records:    []domain.SBOMEntry{{Version: "existing", SHA256: storedChecksum, BomResult: storedJSON}},
	}
	svc := NewService(repo, NewInMemoryCache())
	canonical := makeBOM("1.2-a", []string{"v1.2-a", "v1.2-b"})
	version, err := svc.FindVersionForSBOM(wsID, HashSBOM(canonical), canonical)
	require.NoError(t, err)
	assert.Equal(t, domain.Version("existing"), version)
}

func TestService_CompatibilityIndexTracksHistoryAndMutations(t *testing.T) {
	makeBOM := func(id, suggested, other string, candidates ...string) FormattedSBOM {
		return FormattedSBOM{ComponentInfo: map[string]Component{
			"pkg": {Vulns: []Vuln{{ID: id, SuggestFixVersion: suggested, OtherFixVersions: other, FixVersions: candidates}}},
		}}
	}
	oldData := makeBOM("CVE-1", "1.2-b", "1.2-a")
	oldJSON, err := json.Marshal(oldData)
	require.NoError(t, err)
	oldChecksum := HashSBOM(oldData)
	loadErr := errors.New("temporary history read failure")
	repo := &checksumTrackingRepo{
		byChecksum: map[string]domain.Version{oldChecksum: "oldest"},
		records: []domain.SBOMEntry{
			{Version: "corrupt", BomResult: json.RawMessage("{")},
			{Version: "oldest", SHA256: oldChecksum, BomResult: oldJSON},
			{Version: "next", SHA256: oldChecksum, BomResult: oldJSON},
		},
		historyErr: loadErr,
	}
	cache := NewInMemoryCache()
	svc := NewService(repo, cache)

	legacy := makeBOM("CVE-1", "1.2-a", "1.2-b", "1.2-a", "1.2-b")
	first := makeBOM("CVE-2", "1.2-a", "1.2-b", "1.2-a", "1.2-b")
	second := makeBOM("CVE-3", "1.2-a", "1.2-b", "1.2-a", "1.2-b")

	lookup := func(projectID domain.ProjectID, bom FormattedSBOM, want string) {
		t.Helper()
		got, err := svc.FindVersionForSBOM(projectID, HashSBOM(bom), bom)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	_, err = svc.FindVersionForSBOM(wsID, HashSBOM(first), first)
	require.ErrorIs(t, err, loadErr)
	repo.historyErr = nil

	lookup(wsID, legacy, "oldest")
	lookup(wsID, first, "")
	lookup(wsID, second, "")
	require.NoError(t, svc.SaveParsed(wsID, "saved", first, HashSBOM(first), time.Time{}))

	// Different historical display order misses the saved exact checksum.
	alias := makeBOM("CVE-2", "1.2-b", "1.2-a", "1.2-a", "1.2-b")
	lookup(wsID, alias, "saved")
	require.NoError(t, svc.Rename(wsID, "saved", "renamed"))
	lookup(wsID, alias, "renamed")
	require.NoError(t, svc.Delete(wsID, "renamed"))
	lookup(wsID, alias, "")

	// Oldest matching entry stays first when renamed and gives way when deleted.
	require.NoError(t, svc.Rename(wsID, "oldest", "first"))
	lookup(wsID, legacy, "first")
	require.NoError(t, svc.Delete(wsID, "first"))
	lookup(wsID, legacy, "next")
	require.NoError(t, svc.Delete(wsID, "next"))
	lookup(wsID, legacy, "")
	assert.Equal(t, 2, repo.historyReads, "one retry, then only digest lookups")

	lookup(wsID+1, legacy, "")
	lookup(wsID+1, legacy, "")
	assert.Equal(t, 3, repo.historyReads, "an empty index is cached per project")
	cache.ReplaceProject(wsID, nil)
	repo.records = nil
	lookup(wsID, legacy, "")
	assert.Equal(t, 4, repo.historyReads, "workspace reload invalidates the index")
	cache.DeleteProject(wsID)
	repo.historyErr = loadErr
	_, err = svc.FindVersionForSBOM(wsID, HashSBOM(legacy), legacy)
	require.ErrorIs(t, err, loadErr, "project deletion cannot leave a warm index")
	repo.historyErr = nil
	lookup(wsID, legacy, "")
	lookup(wsID, legacy, "")
	assert.Equal(t, 6, repo.historyReads, "the project index is rebuilt after recovery")
}

func TestService_SaveParsed_ConcurrentSameChecksumInsertsOnce(t *testing.T) {
	// Arrange: two concurrent uploads of the same file (same SHA-256), as when
	// two browser tabs submit simultaneously.
	repo := &checksumTrackingRepo{byChecksum: map[string]domain.Version{}}
	svc := NewService(repo, NewInMemoryCache())

	checksum := HashSBOM(FormattedSBOM{})
	errs := make(chan error, 2)

	var wg sync.WaitGroup
	for _, version := range []domain.Version{"tab-1", "tab-2"} {
		wg.Add(1)
		go func(v domain.Version) {
			defer wg.Done()
			errs <- svc.SaveParsed(wsID, v, FormattedSBOM{}, checksum, time.Time{})
		}(version)
	}
	wg.Wait()
	close(errs)

	// Assert: exactly one insert; the loser gets DuplicateSHA256Error.
	var okCount, dupCount int
	for err := range errs {
		var dup *DuplicateSHA256Error
		switch {
		case err == nil:
			okCount++
		case errors.As(err, &dup):
			dupCount++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}

	assert.Equal(t, 1, okCount, "exactly one request must win")
	assert.Equal(t, 1, dupCount, "the other must get DuplicateSHA256Error")
	assert.Equal(t, 1, repo.inserts, "only one row may reach the repository")
}
