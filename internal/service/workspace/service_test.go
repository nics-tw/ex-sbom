// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package psvc

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"
)

// fakeRepo is an in-memory Repository that can pause inside GetAllByProject so
// tests can interleave a concurrent save with an in-flight load deterministically.
type fakeRepo struct {
	mu      sync.Mutex
	records map[domain.ProjectID][]domain.SBOMEntry

	getAllStarted chan struct{}
	getAllRelease chan struct{}
	getAllErr     error
}

var errFakeDB = errors.New("fake db failure")

func newFakeRepo() *fakeRepo {
	return &fakeRepo{records: make(map[domain.ProjectID][]domain.SBOMEntry)}
}

func (f *fakeRepo) CreateSBOM(projectID domain.ProjectID, version domain.Version, result any, _ time.Time, checksum string) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[projectID] = append(f.records[projectID], domain.SBOMEntry{
		Version:   version,
		BomResult: raw,
		SHA256:    checksum,
	})
	return nil
}

func (f *fakeRepo) GetAllByProject(projectID domain.ProjectID) ([]domain.SBOMEntry, error) {
	if f.getAllErr != nil {
		return nil, f.getAllErr
	}

	f.mu.Lock()
	snapshot := append([]domain.SBOMEntry(nil), f.records[projectID]...)
	f.mu.Unlock()

	// simulate a slow DB read: expose the snapshot moment, then wait
	if f.getAllStarted != nil {
		f.getAllStarted <- struct{}{}
		<-f.getAllRelease
	}

	return snapshot, nil
}

func (f *fakeRepo) FindVersionBySHA256(domain.ProjectID, domain.SHA256) (domain.Version, error) {
	return "", repository.ErrVersionNotFound
}

func (f *fakeRepo) CreateProject(domain.ProjectName) (domain.ProjectID, error) { return 0, nil }
func (f *fakeRepo) UpdateProjectName(domain.ProjectID, domain.ProjectName) error {
	return nil
}
func (f *fakeRepo) DeleteProject(domain.ProjectID) error       { return nil }
func (f *fakeRepo) GetProjects() ([]domain.ProjectInfo, error) { return nil, nil }
func (f *fakeRepo) DeleteSBOM(domain.ProjectID, domain.Version) error {
	return nil
}
func (f *fakeRepo) RenameVersion(domain.ProjectID, domain.Version, domain.Version) error {
	return nil
}
func (f *fakeRepo) GetAllVersions(domain.ProjectID) ([]domain.VersionInfo, error) {
	return nil, nil
}
func (f *fakeRepo) GetLatestAll() (domain.ProjectID, []domain.SBOMEntry, error) {
	return 0, nil, nil
}

// TestLoadDoesNotClobberConcurrentSave reproduces the save/load race: a Load
// whose DB snapshot was taken before a concurrent save finishes must not wipe
// the newly saved version from the cache.
func TestLoadDoesNotClobberConcurrentSave(t *testing.T) {
	const projectID domain.ProjectID = 1

	repo := newFakeRepo()
	cache := ssbom.NewInMemoryCache()
	projectSvc := New(repo, cache)
	sbomSvc := ssbom.NewService(repo, cache)

	// v1 already persisted before the load starts
	if err := repo.CreateSBOM(projectID, "v1", ssbom.FormattedSBOM{Components: []string{"a"}}, time.Time{}, "sha-v1"); err != nil {
		t.Fatal(err)
	}

	repo.getAllStarted = make(chan struct{})
	repo.getAllRelease = make(chan struct{})

	loadDone := make(chan error, 1)
	go func() {
		_, _, err := projectSvc.Load(projectID)
		loadDone <- err
	}()

	// wait until Load has taken its DB snapshot (which does not contain v2)
	<-repo.getAllStarted
	repo.getAllStarted = nil

	// concurrent save of a new version while the load is still in flight
	saveDone := make(chan error, 1)
	go func() {
		saveDone <- sbomSvc.SaveParsed(projectID, "v2", ssbom.FormattedSBOM{Components: []string{"b"}}, "sha-v2", time.Time{})
	}()

	// give the save a chance to run as far as it can before the load resumes;
	// with per-project locking it must block until the load has finished
	time.Sleep(50 * time.Millisecond)
	close(repo.getAllRelease)

	if err := <-loadDone; err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if err := <-saveDone; err != nil {
		t.Fatalf("SaveParsed failed: %v", err)
	}

	if _, ok := cache.Get(projectID, "v1"); !ok {
		t.Error("v1 missing from cache after interleaved save/load")
	}
	if _, ok := cache.Get(projectID, "v2"); !ok {
		t.Error("v2 missing from cache: stale load snapshot clobbered the concurrent save")
	}
}

// addRawRecord injects a persisted record with arbitrary raw JSON, bypassing
// CreateSBOM's marshalling, to simulate on-disk corruption or schema drift.
func (f *fakeRepo) addRawRecord(projectID domain.ProjectID, version domain.Version, raw []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[projectID] = append(f.records[projectID], domain.SBOMEntry{
		Version:   version,
		BomResult: raw,
	})
}

// TestLoadMixedValidAndCorruptedRecords: corrupted persisted JSON must be
// reported (degraded state), valid versions must still load, and the caller
// must be able to tell corruption apart from absence.
func TestLoadMixedValidAndCorruptedRecords(t *testing.T) {
	const projectID domain.ProjectID = 1

	repo := newFakeRepo()
	cache := ssbom.NewInMemoryCache()
	projectSvc := New(repo, cache)

	if err := repo.CreateSBOM(projectID, "v-good-1", ssbom.FormattedSBOM{Components: []string{"a"}}, time.Time{}, "sha-1"); err != nil {
		t.Fatal(err)
	}
	repo.addRawRecord(projectID, "v-corrupt", []byte(`{"components": not-json`))
	if err := repo.CreateSBOM(projectID, "v-good-2", ssbom.FormattedSBOM{Components: []string{"b"}}, time.Time{}, "sha-2"); err != nil {
		t.Fatal(err)
	}

	names, corrupted, err := projectSvc.Load(projectID)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(names) != 2 || names[0] != "v-good-1" || names[1] != "v-good-2" {
		t.Errorf("valid versions must still load, got %v", names)
	}
	if len(corrupted) != 1 || corrupted[0] != "v-corrupt" {
		t.Errorf("corrupted version must be reported, got %v", corrupted)
	}

	if _, ok := cache.Get(projectID, "v-good-1"); !ok {
		t.Error("v-good-1 missing from cache")
	}
	if _, ok := cache.Get(projectID, "v-corrupt"); ok {
		t.Error("corrupted record must not be cached")
	}
}

// TestLoadKeepsCacheIntactWhenRepoFails: if the DB read fails outright, the
// previously cached state must survive untouched.
func TestLoadKeepsCacheIntactWhenRepoFails(t *testing.T) {
	const projectID domain.ProjectID = 1

	repo := newFakeRepo()
	repo.getAllErr = errFakeDB
	cache := ssbom.NewInMemoryCache()
	projectSvc := New(repo, cache)

	cache.Set(projectID, "v-cached", ssbom.FormattedSBOM{Components: []string{"a"}})

	_, _, err := projectSvc.Load(projectID)
	if err == nil {
		t.Fatal("expected error from failing repo")
	}

	if _, ok := cache.Get(projectID, "v-cached"); !ok {
		t.Error("cache must keep its original state when the load fails")
	}
}
