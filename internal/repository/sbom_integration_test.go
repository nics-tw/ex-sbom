// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build integration

package repository

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"ex-sbom/internal/db"
	"ex-sbom/internal/domain"

	gorm_duckdb "github.com/alifiroozi80/duckdb"
	_ "github.com/marcboeker/go-duckdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// openRepo initializes a real DuckDB at path (running all goose migrations) and
// returns a repository bound to it. Callers are responsible for db.Close().
func openRepo(t *testing.T, path string) *SBOMRepository {
	t.Helper()
	require.NoError(t, db.Init(path))
	return NewSBOMRepository(db.GormDB)
}

// TestDuckDBPersistence is an end-to-end integration test against a temporary
// on-disk DuckDB. Unlike the stub-repository tests, it exercises the real
// schema, raw SQL, JSON (de)serialization, close/reopen persistence,
// transactions (rename), and uniqueness handling — the core of this PR.
//
// The test models a stateful lifecycle, so the subtests are ordered and share
// state: each t.Run builds on the previous one. Every subtest follows the
// Arrange-Act-Assert (AAA) structure, and independent error cases are expressed
// as table-driven checks.
func TestDuckDBPersistence(t *testing.T) {
	// Arrange: open a fresh DuckDB and keep a handle to shared state across the
	// ordered subtests below.
	path := filepath.Join(t.TempDir(), "integration.duckdb")
	repo := openRepo(t, path)
	t.Cleanup(db.Close)

	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	result := map[string]any{"components": []string{"libx", "liby"}, "count": 2}

	var pid, pidB domain.ProjectID

	t.Run("migration seeds default project", func(t *testing.T) {
		// Arrange: nothing extra — migrations ran during openRepo.

		// Act
		projects, err := repo.GetProjects()

		// Assert
		require.NoError(t, err)
		require.NotEmpty(t, projects, "migration should seed a default project")
		assert.Equal(t, "default", projects[0].Name)
		assert.NotEmpty(t, projects[0].UUID, "seeded project should have a uuid")
	})

	t.Run("create project", func(t *testing.T) {
		// Arrange: fresh project name.

		// Act
		id, err := repo.CreateProject("proj-a")

		// Assert
		require.NoError(t, err)
		require.NotZero(t, id)
		pid = id
	})

	t.Run("duplicate project name is rejected", func(t *testing.T) {
		// Arrange: names that must collide with existing projects.
		cases := []struct {
			name    string
			project string
		}{
			{"same as newly created", "proj-a"},
			{"same as seeded default", "default"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				// Act
				_, err := repo.CreateProject(tc.project)

				// Assert
				assert.ErrorIs(t, err, domain.ErrDuplicateProjectName)
			})
		}
	})

	t.Run("create SBOM and serialize payload", func(t *testing.T) {
		// Arrange: use the project created above.

		// Act
		err := repo.CreateSBOM(pid, "v1", result, ts, "sha-v1")

		// Assert
		require.NoError(t, err)
	})

	t.Run("duplicate (project, version) is rejected", func(t *testing.T) {
		// Arrange: same (project, version) as the record just written.

		// Act
		err := repo.CreateSBOM(pid, "v1", result, ts, "sha-other")

		// Assert
		assert.ErrorIs(t, err, ErrVersionExists)
	})

	t.Run("read back and deserialize round-trip", func(t *testing.T) {
		// Arrange: the single record written above.

		// Act
		entries, err := repo.GetAllByProject(pid)

		// Assert
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "v1", entries[0].Version)
		assert.Equal(t, "sha-v1", entries[0].SHA256)

		var decoded map[string]any
		require.NoError(t, json.Unmarshal(entries[0].BomResult, &decoded))
		assert.EqualValues(t, 2, decoded["count"])
		assert.Equal(t, []any{"libx", "liby"}, decoded["components"])

		versions, err := repo.GetAllVersions(pid)
		require.NoError(t, err)
		require.Len(t, versions, 1)
		assert.Equal(t, "v1", versions[0].Version)
		assert.False(t, versions[0].CreatedAt.IsZero(), "created_at should be populated")

		found, err := repo.FindVersionBySHA256(pid, "sha-v1")
		require.NoError(t, err)
		assert.Equal(t, "v1", found)
	})

	t.Run("rename version preserves checksum and payload", func(t *testing.T) {
		// Arrange: v1 exists from the previous subtest.

		// Act
		err := repo.RenameVersion(pid, "v1", "v2")

		// Assert
		require.NoError(t, err)

		renamed, err := repo.FindVersionBySHA256(pid, "sha-v1")
		require.NoError(t, err)
		assert.Equal(t, "v2", renamed, "rename must preserve checksum and payload under the new version")
	})

	t.Run("rename missing version returns ErrVersionNotFound", func(t *testing.T) {
		// Arrange: "v1" no longer exists — it was renamed to "v2" above.

		// Act
		err := repo.RenameVersion(pid, "v1", "v3")

		// Assert
		assert.ErrorIs(t, err, ErrVersionNotFound,
			"renaming a deleted/stale version must return ErrVersionNotFound")
	})

	t.Run("rename to an existing version rolls back", func(t *testing.T) {
		require.NoError(t, repo.CreateSBOM(pid, "v3", result, ts, "sha-v3"))
		assert.ErrorIs(t, repo.RenameVersion(pid, "v2", "v3"), ErrVersionExists)

		entries, err := repo.GetAllByProject(pid)
		require.NoError(t, err)
		require.Len(t, entries, 2)
		assert.Equal(t, domain.Version("v2"), entries[0].Version)
		assert.Equal(t, domain.Version("v3"), entries[1].Version)
		require.NoError(t, repo.DeleteSBOM(pid, "v3"))
	})

	t.Run("lookup by unknown checksum returns ErrVersionNotFound", func(t *testing.T) {
		// Arrange: a checksum that was never stored.

		// Act
		_, err := repo.FindVersionBySHA256(pid, "sha-missing")

		// Assert
		assert.ErrorIs(t, err, ErrVersionNotFound)
	})

	t.Run("data persists across close and reopen", func(t *testing.T) {
		otherID, err := repo.CreateProject("reopen-project")
		require.NoError(t, err)
		require.NoError(t, repo.CreateSBOM(otherID, "other-v1", result, ts, "sha-other"))
		// Arrange: close the current DB and reopen the same file.
		db.Close()
		repo = openRepo(t, path)

		// Act
		reopened, err := repo.GetAllByProject(pid)

		// Assert
		require.NoError(t, err)
		require.Len(t, reopened, 1, "SBOM must survive a close/reopen cycle")
		assert.Equal(t, "v2", reopened[0].Version)
		assert.Equal(t, "sha-v1", reopened[0].SHA256)
		otherEntries, err := repo.GetAllByProject(otherID)
		require.NoError(t, err)
		require.Len(t, otherEntries, 1)
		assert.Equal(t, domain.Version("other-v1"), otherEntries[0].Version)

		stillThere, err := repo.GetProjects()
		require.NoError(t, err)
		assert.True(t, containsProject(stillThere, pid), "project must survive a close/reopen cycle")
	})

	t.Run("project existence and not-found errors", func(t *testing.T) {
		// Arrange: an id that was never allocated.
		const missing domain.ProjectID = 999999

		// Act + Assert: existence lookup distinguishes real from missing ids.
		exists, err := repo.ProjectExists(pid)
		require.NoError(t, err)
		assert.True(t, exists)

		exists, err = repo.ProjectExists(missing)
		require.NoError(t, err)
		assert.False(t, exists)

		// Act + Assert: mutating a missing project reports not-found instead
		// of silently succeeding.
		assert.ErrorIs(t, repo.UpdateProjectName(missing, "ghost"), domain.ErrProjectNotFound)
		// Not-found takes precedence over a name conflict.
		assert.ErrorIs(t, repo.UpdateProjectName(missing, "proj-a"), domain.ErrProjectNotFound)
		assert.ErrorIs(t, repo.DeleteProject(missing), domain.ErrProjectNotFound)
	})

	t.Run("rename project that owns SBOM records", func(t *testing.T) {
		// Arrange: pid still owns v2. DuckDB rewrites an UPDATE of an indexed
		// column as delete+insert, which trips the sbom_records FK — so this
		// guards against ever putting a unique index on project_name.

		// Act + Assert
		require.NoError(t, repo.UpdateProjectName(pid, "proj-a-renamed"))
		require.NoError(t, repo.UpdateProjectName(pid, "proj-a"))

		entries, err := repo.GetAllByProject(pid)
		require.NoError(t, err)
		require.Len(t, entries, 1, "renaming a project must not touch its SBOM records")
	})

	t.Run("update project name", func(t *testing.T) {
		// Arrange: a second project to rename.
		id, err := repo.CreateProject("proj-b")
		require.NoError(t, err)
		pidB = id

		// Act + Assert: renaming onto an existing name is rejected.
		err = repo.UpdateProjectName(pidB, "proj-a")
		assert.ErrorIs(t, err, domain.ErrDuplicateProjectName, "renaming onto an existing name must be rejected")

		// Act + Assert: renaming to a free name succeeds.
		require.NoError(t, repo.UpdateProjectName(pidB, "proj-b-renamed"))
		after, err := repo.GetProjects()
		require.NoError(t, err)
		assert.Equal(t, "proj-b-renamed", projectName(after, pidB))
	})

	t.Run("logical delete hides old ID and permits name reuse", func(t *testing.T) {
		oldID, err := repo.CreateProject("reusable")
		require.NoError(t, err)
		require.NoError(t, repo.CreateSBOM(oldID, "stored-v1", result, ts, "sha-stored"))
		require.NoError(t, repo.DeleteProject(oldID))

		exists, err := repo.ProjectExists(oldID)
		require.NoError(t, err)
		assert.False(t, exists)
		projects, err := repo.GetProjects()
		require.NoError(t, err)
		assert.False(t, containsProject(projects, oldID))
		entries, err := repo.GetAllByProject(oldID)
		require.NoError(t, err)
		assert.Empty(t, entries)
		versions, err := repo.GetAllVersions(oldID)
		require.NoError(t, err)
		assert.Empty(t, versions)
		_, err = repo.FindVersionBySHA256(oldID, "sha-stored")
		assert.ErrorIs(t, err, ErrVersionNotFound)
		assert.ErrorIs(t, repo.RenameVersion(oldID, "stored-v1", "stored-v2"), ErrVersionNotFound)
		assert.ErrorIs(t, repo.DeleteSBOM(oldID, "stored-v1"), ErrVersionNotFound)
		assert.ErrorIs(t, repo.CreateSBOM(oldID, "new-v1", result, ts, "sha-new"), domain.ErrProjectNotFound)
		assert.ErrorIs(t, repo.UpdateProjectName(oldID, "still-old"), domain.ErrProjectNotFound)

		var retained int
		require.NoError(t, db.DB.QueryRow("SELECT COUNT(*) FROM sbom_records WHERE project_id = ?", oldID).Scan(&retained))
		assert.Equal(t, 1, retained, "deleted project's committed SBOM remains recoverable")
		newID, err := repo.CreateProject("reusable")
		require.NoError(t, err)
		assert.NotEqual(t, oldID, newID)
	})

	t.Run("delete SBOM then project", func(t *testing.T) {
		// Arrange: v2 exists under pid.

		// Act + Assert: delete succeeds, second delete is a not-found.
		require.NoError(t, repo.DeleteSBOM(pid, "v2"))
		err := repo.DeleteSBOM(pid, "v2")
		assert.ErrorIs(t, err, ErrVersionNotFound, "deleting a missing version must return ErrVersionNotFound")

		empty, err := repo.GetAllByProject(pid)
		require.NoError(t, err)
		assert.Empty(t, empty)

		// Act + Assert: deleting the project removes it entirely.
		require.NoError(t, repo.DeleteProject(pid))
		final, err := repo.GetProjects()
		require.NoError(t, err)
		assert.False(t, containsProject(final, pid), "deleted project must be gone")

		// Act + Assert: a second delete is a not-found, not a silent success.
		assert.ErrorIs(t, repo.DeleteProject(pid), domain.ErrProjectNotFound)
		exists, err := repo.ProjectExists(pid)
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

func TestProjectDeleteFailedWritePreservesSBOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "read-only.duckdb")
	repo := openRepo(t, path)
	pid, err := repo.CreateProject("read-only-project")
	require.NoError(t, err)
	require.NoError(t, repo.CreateSBOM(pid, "v1", map[string]any{"components": []string{"libx"}}, time.Time{}, "sha-v1"))
	db.Close()

	readOnlyDB, err := sql.Open("duckdb", path+"?access_mode=READ_ONLY")
	require.NoError(t, err)
	defer readOnlyDB.Close()
	readOnlyGorm, err := gorm.Open(gorm_duckdb.New(gorm_duckdb.Config{Conn: readOnlyDB}), &gorm.Config{})
	require.NoError(t, err)
	readOnlyRepo := NewSBOMRepository(readOnlyGorm)
	require.Error(t, readOnlyRepo.DeleteProject(pid))

	var retained int
	require.NoError(t, readOnlyDB.QueryRow("SELECT COUNT(*) FROM sbom_records WHERE project_id = ?", pid).Scan(&retained))
	assert.Equal(t, 1, retained)
	var active int
	require.NoError(t, readOnlyDB.QueryRow("SELECT COUNT(*) FROM projects WHERE id = ? AND deleted_at IS NULL", pid).Scan(&active))
	assert.Equal(t, 1, active)
}

func containsProject(projects []domain.ProjectInfo, id domain.ProjectID) bool {
	for _, p := range projects {
		if p.ID == id {
			return true
		}
	}
	return false
}

func projectName(projects []domain.ProjectInfo, id domain.ProjectID) string {
	for _, p := range projects {
		if p.ID == id {
			return p.Name
		}
	}
	return ""
}
