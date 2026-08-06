// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package psvc

import (
	"encoding/json"
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
}

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
func (f *fakeRepo) DeleteProject(domain.ProjectID) error          { return nil }
func (f *fakeRepo) GetProjects() ([]domain.ProjectInfo, error)    { return nil, nil }
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
		_, err := projectSvc.Load(projectID)
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
