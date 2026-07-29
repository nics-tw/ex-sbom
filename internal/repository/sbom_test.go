// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package repository

import (
	"path/filepath"
	"testing"
	"time"

	"ex-sbom/internal/db"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRepo spins up a real, isolated DuckDB (with migrations applied) and
// returns a repository plus the seeded default project id.
func newTestRepo(t *testing.T) (*SBOMRepository, int64) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.duckdb")
	require.NoError(t, db.Init(path))

	var projectID int64
	require.NoError(t, db.DB.QueryRow(
		`SELECT id FROM projects ORDER BY id LIMIT 1`,
	).Scan(&projectID))

	return NewSBOMRepository(db.GormDB), projectID
}

// TestCreateSBOM_ZeroTimestampStoresNull verifies that an SBOM parsed without a
// timestamp (e.g. an SPDX document lacking a creation date, which yields
// time.Time{}) is persisted as SQL NULL rather than the year-0001 zero value.
func TestCreateSBOM_ZeroTimestampStoresNull(t *testing.T) {
	repo, projectID := newTestRepo(t)

	err := repo.CreateSBOM(projectID, "no-ts", map[string]any{"k": "v"}, time.Time{}, "sha-zero")
	require.NoError(t, err)

	var isNull bool
	require.NoError(t, db.DB.QueryRow(
		`SELECT bom_timestamp IS NULL FROM sbom_records WHERE project_id = ? AND version = ?`,
		projectID, "no-ts",
	).Scan(&isNull))

	assert.True(t, isNull, "zero timestamp must be stored as NULL, not year 0001")
}

// TestCreateSBOM_NonZeroTimestampPersisted verifies a real timestamp is stored.
func TestCreateSBOM_NonZeroTimestampPersisted(t *testing.T) {
	repo, projectID := newTestRepo(t)

	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	err := repo.CreateSBOM(projectID, "with-ts", map[string]any{"k": "v"}, ts, "sha-nonzero")
	require.NoError(t, err)

	var isNull bool
	require.NoError(t, db.DB.QueryRow(
		`SELECT bom_timestamp IS NULL FROM sbom_records WHERE project_id = ? AND version = ?`,
		projectID, "with-ts",
	).Scan(&isNull))

	assert.False(t, isNull, "non-zero timestamp must be persisted")
}
