// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ex-sbom/internal/db"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"
	"ex-sbom/tests/perf"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var shape perf.Shape
	path := flag.String("db", "", "path to a new DuckDB file")
	flag.IntVar(&shape.Projects, "projects", 1, "number of populated fixture projects")
	flag.IntVar(&shape.Versions, "versions", 4, "versions per project")
	flag.IntVar(&shape.Components, "components", 100, "components per version")
	flag.IntVar(&shape.Fanout, "fanout", 2, "maximum outgoing edges per component")
	flag.Parse()
	if *path == "" || shape.Projects < 1 || shape.Versions < 2 || shape.Components < 2 || shape.Fanout < 0 {
		return errors.New("require a new -db path, projects >= 1, versions >= 2, components >= 2 and fanout >= 0")
	}

	if _, err := os.Lstat(*path); err == nil {
		return fmt.Errorf("database path already exists: %s", *path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Dir(*path), ".perf-seed-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	temporaryDB := filepath.Join(dir, "fixture.duckdb")
	if err := db.Init(temporaryDB); err != nil {
		return err
	}
	defer func() { _ = db.DB.Close() }()

	repo := repository.NewSBOMRepository(db.GormDB)
	manifest := struct {
		perf.Shape
		ProjectID     int64  `json:"target_project_id"`
		ProjectName   string `json:"target_project_name"`
		FirstVersion  string `json:"first_version"`
		SecondVersion string `json:"second_version"`
		TargetEdges   int    `json:"edges_in_first_version"`
		TargetBytes   int    `json:"first_version_processed_json_bytes"`
		TotalBytes    int64  `json:"total_processed_json_bytes"`
		SearchTerm    string `json:"search_term"`
	}{
		Shape: shape, FirstVersion: perf.Version(shape.Versions - 1), SecondVersion: perf.Version(shape.Versions - 2), SearchTerm: perf.SearchTerm,
	}
	for project := range shape.Projects {
		name := fmt.Sprintf("Performance fixture %06d", project)
		id, err := repo.CreateProject(name)
		if err != nil {
			return err
		}
		for version := range shape.Versions {
			bom := perf.BOM(project, version, shape)
			payload, err := json.Marshal(bom)
			if err != nil {
				return err
			}
			manifest.TotalBytes += int64(len(payload))
			if project == 0 && version == shape.Versions-1 {
				manifest.ProjectID = id
				manifest.ProjectName = name
				for _, targets := range bom.Dependency {
					manifest.TargetEdges += len(targets)
				}
				manifest.TargetBytes = len(payload)
			}
			timestamp := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(version) * time.Hour)
			if err := repo.CreateSBOM(id, perf.Version(version), json.RawMessage(payload), timestamp, ssbom.HashSBOM(bom)); err != nil {
				return fmt.Errorf("seed %s, version %d: %w", name, version, err)
			}
		}
	}
	// Publish the closed database atomically; a concurrent creator wins
	// instead of having their existing database overwritten.
	if err := db.DB.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryDB, *path); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(manifest)
}
