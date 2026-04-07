// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"sync"

	"ex-sbom/internal/domain"
)

// Cache is a thread-safe in-memory store for FormattedSBOM objects, keyed by project and filename.
type Cache interface {
	Get(projectID domain.ProjectID, name domain.Version) (FormattedSBOM, bool)
	Set(projectID domain.ProjectID, name domain.Version, sbom FormattedSBOM)
	Delete(projectID domain.ProjectID, name domain.Version)
	DeleteProject(projectID domain.ProjectID)
	Keys(projectID domain.ProjectID) []domain.Version
	All(projectID domain.ProjectID) map[domain.Version]FormattedSBOM
}

type inMemoryCache struct {
	mu   sync.RWMutex
	data map[domain.ProjectID]map[domain.Version]FormattedSBOM
}

// NewInMemoryCache returns a new in-memory Cache implementation.
func NewInMemoryCache() Cache {
	return &inMemoryCache{
		data: make(map[domain.ProjectID]map[domain.Version]FormattedSBOM),
	}
}

func (c *inMemoryCache) Get(projectID domain.ProjectID, name domain.Version) (FormattedSBOM, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sbom, ok := c.data[projectID][name]
	return sbom, ok
}

func (c *inMemoryCache) Set(projectID domain.ProjectID, name domain.Version, sbom FormattedSBOM) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.data[projectID] == nil {
		c.data[projectID] = make(map[domain.Version]FormattedSBOM)
	}

	c.data[projectID][name] = sbom
}

func (c *inMemoryCache) Delete(projectID domain.ProjectID, name domain.Version) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data[projectID], name)
}

func (c *inMemoryCache) DeleteProject(projectID domain.ProjectID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, projectID)
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
