//go:build unit

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"ex-sbom/client/first"
	"ex-sbom/internal/domain"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"

	"github.com/stretchr/testify/require"
)

type startupRepository struct {
	repository.Repository
	projects []domain.ProjectInfo
	records  map[domain.ProjectID][]domain.SBOMEntry
}

func (r startupRepository) GetProjects() ([]domain.ProjectInfo, error) { return r.projects, nil }
func (r startupRepository) GetAllByProject(id domain.ProjectID) ([]domain.SBOMEntry, error) {
	return r.records[id], nil
}

func TestLoadInitialDataAllProjects(t *testing.T) {
	repo := startupRepository{
		projects: []domain.ProjectInfo{{ID: 1}, {ID: 2}},
		records: map[domain.ProjectID][]domain.SBOMEntry{
			1: {{Version: "first-v1", BomResult: json.RawMessage(`{"components":["a"]}`)}},
			2: {{Version: "second-v1", BomResult: json.RawMessage(`{"components":["b"]}`)}},
		},
	}
	cache := ssbom.NewInMemoryCache()
	loadInitialData(repo, cache)

	svc := ssbom.NewService(repo, cache)
	bom, err := svc.Get(2, "second-v1")
	if err != nil || len(bom.Components) != 1 || bom.Components[0] != "b" {
		t.Fatalf("second project's SBOM unavailable after startup: bom=%+v err=%v", bom, err)
	}
}

func TestArchiveIndexCommandRunsBeforeApplicationStartup(t *testing.T) {
	t.Setenv("BIND_ADDR", "192.0.2.1")
	t.Setenv("DB_PATH", filepath.Join(t.TempDir(), "data.duckdb"))
	dir := t.TempDir()
	dest := filepath.Join(t.TempDir(), "snapshot")
	t.Cleanup(func() {
		if runtime.GOOS == "windows" {
			if _, err := os.Stat(dest); err == nil {
				output, err := exec.Command("icacls", dest, "/reset", "/T", "/Q").CombinedOutput()
				require.NoError(t, err, "%s", output)
			}
			return
		}
		_ = os.Chmod(dest, 0700)
	})
	var out, diagnostics bytes.Buffer
	handled, err := runArchiveIndexCommand(context.Background(), []string{"lev-index", "build", "--archive", dir, "--as-of", first.FirstArchiveDay, "--output", dest}, &out, &diagnostics)
	require.NoError(t, err)
	require.True(t, handled)
	require.Contains(t, out.String(), dest)
	require.NoFileExists(t, os.Getenv("DB_PATH"))

	handled, err = runArchiveIndexCommand(context.Background(), []string{"lev-index", "build"}, &out, &diagnostics)
	require.Error(t, err)
	require.True(t, handled)
	handled, err = runArchiveIndexCommand(context.Background(), nil, &out, &diagnostics)
	require.NoError(t, err)
	require.False(t, handled)
}
