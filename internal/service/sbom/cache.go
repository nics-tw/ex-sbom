// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"encoding/json"
	"maps"
	"sync"

	"ex-sbom/internal/domain"
)

// Cache is a thread-safe in-memory store for FormattedSBOM objects, keyed by project and filename.
type Cache interface {
	Get(projectID domain.ProjectID, name domain.Version) (FormattedSBOM, bool)
	Set(projectID domain.ProjectID, name domain.Version, sbom FormattedSBOM)
	Delete(projectID domain.ProjectID, name domain.Version)
	Rename(projectID domain.ProjectID, oldName, newName domain.Version)
	DeleteProject(projectID domain.ProjectID)
	ReplaceProject(projectID domain.ProjectID, sboms map[domain.Version]FormattedSBOM)
	ReplaceLoadedProject(projectID domain.ProjectID, sboms map[domain.Version]FormattedSBOM, records []domain.SBOMEntry)
	Keys(projectID domain.ProjectID) []domain.Version
	All(projectID domain.ProjectID) map[domain.Version]FormattedSBOM

	// The compatibility index represents all readable rows from an authoritative project load.
	findCompatibleVersion(projectID domain.ProjectID, checksum, legacy string) (version domain.Version, loaded bool)
	setCompatibilityIndex(projectID domain.ProjectID, rows map[domain.Version]compatibilityEntry, nextOrder int)
	setPersisted(projectID domain.ProjectID, name domain.Version, sbom FormattedSBOM, persistedSHA domain.SHA256)

	// LockProject serializes save/load/delete sequences that must keep the DB
	// and the cache consistent for the same project. Callers must invoke the
	// returned unlock function when the whole sequence (DB access + cache
	// mutation) is done. Individual cache methods stay thread-safe on their
	// own; this lock protects multi-step read-modify-write sequences from
	// interleaving (e.g. a stale DB snapshot overwriting a newer save).
	LockProject(projectID domain.ProjectID) (unlock func())
}

type compatibilityEntry struct {
	checksum     string
	persistedSHA domain.SHA256
	order        int
}

type compatibilityIndex struct {
	rows      map[domain.Version]compatibilityEntry
	nextOrder int
}

type inMemoryCache struct {
	mu            sync.RWMutex
	data          map[domain.ProjectID]map[domain.Version]FormattedSBOM
	compatibility map[domain.ProjectID]*compatibilityIndex

	lockMu       sync.Mutex
	projectLocks map[domain.ProjectID]*sync.Mutex
}

// NewInMemoryCache returns a new in-memory Cache implementation.
func NewInMemoryCache() Cache {
	return &inMemoryCache{
		data:          make(map[domain.ProjectID]map[domain.Version]FormattedSBOM),
		compatibility: make(map[domain.ProjectID]*compatibilityIndex),
		projectLocks:  make(map[domain.ProjectID]*sync.Mutex),
	}
}

func (c *inMemoryCache) LockProject(projectID domain.ProjectID) (unlock func()) {
	c.lockMu.Lock()

	l, ok := c.projectLocks[projectID]
	if !ok {
		l = &sync.Mutex{}
		c.projectLocks[projectID] = l
	}
	c.lockMu.Unlock()

	l.Lock()

	return l.Unlock
}

func (c *inMemoryCache) Get(projectID domain.ProjectID, name domain.Version) (FormattedSBOM, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sbom, ok := c.data[projectID][name]
	return sbom, ok
}

func (c *inMemoryCache) Set(projectID domain.ProjectID, name domain.Version, sbom FormattedSBOM) {
	c.setPersisted(projectID, name, sbom, "")
}

func (c *inMemoryCache) setPersisted(projectID domain.ProjectID, name domain.Version, sbom FormattedSBOM, persistedSHA domain.SHA256) {
	c.mu.Lock()
	if c.compatibility[projectID] == nil {
		c.set(projectID, name, sbom)
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	// Hash without holding the cache-wide mutex. Runtime writers hold LockProject.
	checksum := HashSBOM(normalizeOldFixVersionDisplay(sbom))
	c.mu.Lock()
	defer c.mu.Unlock()
	c.set(projectID, name, sbom)
	if index := c.compatibility[projectID]; index != nil {
		index.rows[name] = compatibilityEntry{checksum: checksum, persistedSHA: persistedSHA, order: index.nextOrder}
		index.nextOrder++
	}
}

// set writes the display cache with mu held.
func (c *inMemoryCache) set(projectID domain.ProjectID, name domain.Version, sbom FormattedSBOM) {
	if c.data[projectID] == nil {
		c.data[projectID] = make(map[domain.Version]FormattedSBOM)
	}
	c.data[projectID][name] = sbom
}

func (c *inMemoryCache) findCompatibleVersion(projectID domain.ProjectID, checksum, legacy string) (domain.Version, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	index := c.compatibility[projectID]
	if index == nil {
		return "", false
	}

	var version domain.Version
	oldest := index.nextOrder
	for name, row := range index.rows {
		if (row.checksum == checksum || row.checksum == legacy) && row.order < oldest {
			version, oldest = name, row.order
		}
	}
	return version, true
}

func (c *inMemoryCache) setCompatibilityIndex(projectID domain.ProjectID, rows map[domain.Version]compatibilityEntry, nextOrder int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.compatibility[projectID] = &compatibilityIndex{rows: rows, nextOrder: nextOrder}
}

func (c *inMemoryCache) Delete(projectID domain.ProjectID, name domain.Version) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data[projectID], name)
	if index := c.compatibility[projectID]; index != nil {
		delete(index.rows, name)
	}
}

func (c *inMemoryCache) Rename(projectID domain.ProjectID, oldName, newName domain.Version) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sbom, ok := c.data[projectID][oldName]; ok {
		delete(c.data[projectID], oldName)
		c.data[projectID][newName] = sbom
	}
	if index := c.compatibility[projectID]; index != nil {
		if row, ok := index.rows[oldName]; ok {
			delete(index.rows, oldName)
			index.rows[newName] = row
		}
	}
}

func (c *inMemoryCache) DeleteProject(projectID domain.ProjectID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, projectID)
	delete(c.compatibility, projectID)
}

// ReplaceProject swaps a complete project snapshot in one write. Copying the
// supplied map also keeps later caller changes from mutating the cache.
func (c *inMemoryCache) ReplaceProject(projectID domain.ProjectID, sboms map[domain.Version]FormattedSBOM) {
	replacement := make(map[domain.Version]FormattedSBOM, len(sboms))
	for version, bom := range sboms {
		replacement[version] = bom
	}

	c.mu.Lock()
	c.data[projectID] = replacement
	delete(c.compatibility, projectID)
	c.mu.Unlock()
}

// ReplaceLoadedProject refreshes a warm compatibility index and keeps a cold
// index lazy. The caller holds LockProject across the repository read and swap.
func (c *inMemoryCache) ReplaceLoadedProject(projectID domain.ProjectID, sboms map[domain.Version]FormattedSBOM, records []domain.SBOMEntry) {
	c.mu.RLock()
	index := c.compatibility[projectID]
	c.mu.RUnlock()

	var replacement *compatibilityIndex
	if index != nil {
		rows := make(map[domain.Version]compatibilityEntry, len(sboms))
		for order, record := range records {
			if _, readable := sboms[record.Version]; !readable {
				continue
			}
			c.mu.RLock()
			entry, exists := index.rows[record.Version]
			c.mu.RUnlock()
			if !exists || record.SHA256 == "" || entry.persistedSHA != record.SHA256 {
				var ok bool
				entry, ok = compatibilityEntryForRecord(record)
				if !ok {
					continue
				}
			}
			entry.order = order
			rows[record.Version] = entry
		}
		replacement = &compatibilityIndex{rows: rows, nextOrder: len(records)}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[projectID] = maps.Clone(sboms)
	if replacement != nil {
		c.compatibility[projectID] = replacement
	}
}

// compatibilityEntryForRecord only normalizes data privately decoded for hashing.
func compatibilityEntryForRecord(record domain.SBOMEntry) (compatibilityEntry, bool) {
	var stored FormattedSBOM
	if err := json.Unmarshal(record.BomResult, &stored); err != nil {
		return compatibilityEntry{}, false
	}
	sortFormattedSBOM(&stored)
	return compatibilityEntry{
		checksum:     HashSBOM(normalizeOldFixVersionDisplay(stored)),
		persistedSHA: record.SHA256,
	}, true
}

func (c *inMemoryCache) Keys(projectID domain.ProjectID) []domain.Version {
	c.mu.RLock()
	defer c.mu.RUnlock()

	proj := c.data[projectID]
	keys := make([]domain.Version, 0, len(proj))
	for k := range proj {
		keys = append(keys, k)
	}

	return keys
}

func (c *inMemoryCache) All(projectID domain.ProjectID) map[domain.Version]FormattedSBOM {
	c.mu.RLock()
	defer c.mu.RUnlock()

	proj := c.data[projectID]
	result := make(map[domain.Version]FormattedSBOM, len(proj))
	for k, v := range proj {
		result[k] = v
	}

	return result
}
