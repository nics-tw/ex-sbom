//go:build unit

package main

import (
	"encoding/json"
	"testing"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"
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
