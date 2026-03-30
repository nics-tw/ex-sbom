// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"ex-sbom/internal/domain"
	"sync"
)

// Cache is a thread-safe in-memory store for FormattedSBOM objects, keyed by workspace and filename.
type Cache interface {
	Get(workspaceID domain.WorkspaceID, name domain.Filename) (FormattedSBOM, bool)
	Set(workspaceID domain.WorkspaceID, name domain.Filename, sbom FormattedSBOM)
	Delete(workspaceID domain.WorkspaceID, name domain.Filename)
	DeleteWorkspace(workspaceID domain.WorkspaceID)
	Keys(workspaceID domain.WorkspaceID) []domain.Filename
	All(workspaceID domain.WorkspaceID) map[domain.Filename]FormattedSBOM
}

type inMemoryCache struct {
	mu   sync.RWMutex
	data map[domain.WorkspaceID]map[domain.Filename]FormattedSBOM
}

// NewInMemoryCache returns a new in-memory Cache implementation.
func NewInMemoryCache() Cache {
	return &inMemoryCache{data: make(map[domain.WorkspaceID]map[domain.Filename]FormattedSBOM)}
}

func (c *inMemoryCache) Get(workspaceID domain.WorkspaceID, name domain.Filename) (FormattedSBOM, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sbom, ok := c.data[workspaceID][name]
	return sbom, ok
}

func (c *inMemoryCache) Set(workspaceID domain.WorkspaceID, name domain.Filename, sbom FormattedSBOM) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.data[workspaceID] == nil {
		c.data[workspaceID] = make(map[domain.Filename]FormattedSBOM)
	}

	c.data[workspaceID][name] = sbom
}

func (c *inMemoryCache) Delete(workspaceID domain.WorkspaceID, name domain.Filename) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data[workspaceID], name)
}

func (c *inMemoryCache) DeleteWorkspace(workspaceID domain.WorkspaceID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, workspaceID)
}

func (c *inMemoryCache) Keys(workspaceID domain.WorkspaceID) []domain.Filename {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ws := c.data[workspaceID]
	keys := make([]domain.Filename, 0, len(ws))
	for k := range ws {
		keys = append(keys, k)
	}

	return keys
}

func (c *inMemoryCache) All(workspaceID domain.WorkspaceID) map[domain.Filename]FormattedSBOM {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ws := c.data[workspaceID]
	result := make(map[domain.Filename]FormattedSBOM, len(ws))
	for k, v := range ws {
		result[k] = v
	}

	return result
}
