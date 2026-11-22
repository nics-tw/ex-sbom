// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package ssbom

import (
	"encoding/json"
	"sync"
	"testing"

	"ex-sbom/internal/domain"
)

func TestCacheReplaceProjectPublishesCompleteSnapshot(t *testing.T) {
	const projectID domain.ProjectID = 42
	cache := NewInMemoryCache()
	old := map[domain.Version]FormattedSBOM{"old-a": {}, "old-b": {}}
	newer := map[domain.Version]FormattedSBOM{"new-a": {}, "new-b": {}}
	cache.ReplaceProject(projectID, old)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			cache.ReplaceProject(projectID, newer)
			cache.ReplaceProject(projectID, old)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			versions := cache.All(projectID)
			if len(versions) != 2 {
				t.Errorf("partial project snapshot: %v", versions)
				return
			}
			_, oldA := versions["old-a"]
			_, oldB := versions["old-b"]
			_, newA := versions["new-a"]
			_, newB := versions["new-b"]
			if !(oldA && oldB || newA && newB) {
				t.Errorf("mixed project snapshot: %v", versions)
				return
			}
		}
	}()
	wg.Wait()

	cache.ReplaceProject(projectID, newer)
	newer["caller-change"] = FormattedSBOM{}
	if _, ok := cache.Get(projectID, "caller-change"); ok {
		t.Fatal("cache retained the caller's mutable map")
	}
}

func TestCacheReplaceLoadedProjectReusesOnlyKnownUnchangedDigest(t *testing.T) {
	const projectID domain.ProjectID = 42
	const version domain.Version = "v1"
	cache := NewInMemoryCache()
	unlock := cache.LockProject(projectID)
	defer unlock()
	for _, tc := range []struct {
		name      string
		previous  string
		loadedSHA string
		reuse     bool
	}{
		{"reuse matching SHA", "unchanged", "unchanged", true},
		{"refresh changed SHA", "unchanged", "changed", false},
		{"refresh unknown SHA", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache.setCompatibilityIndex(projectID, map[domain.Version]compatibilityEntry{
				version: {checksum: "cached-digest", persistedSHA: tc.previous},
			}, 1)
			bom := FormattedSBOM{Components: []string{"z", "a"}}
			body, err := json.Marshal(bom)
			if err != nil {
				t.Fatal(err)
			}
			cache.ReplaceLoadedProject(projectID, map[domain.Version]FormattedSBOM{version: bom}, []domain.SBOMEntry{
				{Version: version, SHA256: tc.loadedSHA, BomResult: body},
			})
			want := ""
			if tc.reuse {
				want = version
			}
			got, loaded := cache.findCompatibleVersion(projectID, "cached-digest", "")
			if !loaded || got != want {
				t.Fatalf("old digest match = %q, %v; want %q", got, loaded, want)
			}
			if !tc.reuse {
				canonical := FormattedSBOM{Components: []string{"a", "z"}}
				got, _ := cache.findCompatibleVersion(projectID, HashSBOM(canonical), "")
				if got != version {
					t.Fatalf("new digest match = %q; want %q", got, version)
				}
			}
			cached, _ := cache.Get(projectID, version)
			if cached.Components[0] != "z" {
				t.Fatal("digest normalization changed the display cache")
			}
		})
	}
}
