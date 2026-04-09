// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ex-sbom/internal/domain"
	reporthandler "ex-sbom/internal/handler/report"
	sbomhandler "ex-sbom/internal/handler/sbom"
	topohandler "ex-sbom/internal/handler/topology"
	projecthandler "ex-sbom/internal/handler/workspace"
	ssbom "ex-sbom/internal/service/sbom"
	psvc "ex-sbom/internal/service/workspace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// noopRepository is a stub that satisfies repository.Repository with safe no-ops.
type noopRepository struct{}

func (r *noopRepository) CreateProject(_ domain.ProjectName) (domain.ProjectID, error) {
	return 1, nil
}
func (r *noopRepository) UpdateProjectName(_ domain.ProjectID, _ domain.ProjectName) error {
	return nil
}
func (r *noopRepository) DeleteProject(_ domain.ProjectID) error { return nil }
func (r *noopRepository) GetProjects() ([]domain.ProjectInfo, error) {
	return []domain.ProjectInfo{}, nil
}
func (r *noopRepository) CreateSBOM(_ domain.ProjectID, _ domain.Version, _ any, _ time.Time, _ string) error {
	return nil
}
func (r *noopRepository) DeleteSBOM(_ domain.ProjectID, _ domain.Version) error { return nil }
func (r *noopRepository) GetLatestAll() (domain.ProjectID, []domain.SBOMEntry, error) {
	return 0, nil, nil
}
func (r *noopRepository) GetLatestByProject(_ domain.ProjectID) ([]domain.SBOMEntry, error) {
	return nil, nil
}
func (r *noopRepository) GetAllVersions(_ domain.ProjectID) ([]domain.VersionInfo, error) {
	return nil, nil
}
func (r *noopRepository) RenameVersion(_ domain.ProjectID, _, _ domain.Version) error {
	return nil
}

// buildTestRouter constructs a router with all handlers wired using a no-op repository.
func buildTestRouter() *gin.Engine {
	repo := &noopRepository{}
	cache := ssbom.NewInMemoryCache()
	sbomSvc := ssbom.NewService(repo, cache)
	projectSvc := psvc.New(repo, cache)

	projectH := projecthandler.New(projectSvc)
	sbomH := sbomhandler.New(sbomSvc, projectSvc)
	topoH := topohandler.New(sbomSvc)
	reportH := reporthandler.New(sbomSvc)

	router := gin.New()
	SetupRouterGroup(router, projectH, sbomH, topoH, reportH)
	return router
}

func TestSetupRouterGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		description    string
	}{
		{
			name:           "list projects",
			method:         "GET",
			path:           "/projects",
			expectedStatus: http.StatusOK,
			description:    "Should route to project.List handler",
		},
		{
			name:           "invalid route",
			method:         "GET",
			path:           "/nonexistent",
			expectedStatus: http.StatusNotFound,
			description:    "Should return 404 for non-existent routes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := buildTestRouter()

			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, tt.description)
		})
	}
}

func TestSetupRouterGroup_RouteRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := buildTestRouter()

	routes := router.Routes()

	expectedRoutes := []struct {
		method string
		path   string
	}{
		{"GET", "/projects"},
		{"POST", "/projects"},
		{"GET", "/projects/:id"},
		{"PUT", "/projects/:id"},
		{"DELETE", "/projects/:id"},
		{"GET", "/projects/:id/diff"},
		{"GET", "/projects/:id/search"},
		{"GET", "/projects/:id/sboms"},
		{"POST", "/projects/:id/sboms"},
		{"POST", "/projects/:id/sboms/preview"},
		{"DELETE", "/projects/:id/sboms/:name"},
		{"PUT", "/projects/:id/sboms/:name"},
		{"GET", "/projects/:id/sboms/:name/report"},
		{"GET", "/projects/:id/versions"},
		{"GET", "/projects/:id/sboms/:name/topology"},
		{"GET", "/projects/:id/sboms/:name/topology/relations"},
		{"GET", "/projects/:id/sboms/:name/topology/component"},
		{"GET", "/projects/:id/sboms/:name/topology/component/vuln-dep"},
	}

	for _, expected := range expectedRoutes {
		found := false
		for _, route := range routes {
			if route.Method == expected.method && route.Path == expected.path {
				found = true
				break
			}
		}
		assert.True(t, found,
			"Route %s %s should be registered", expected.method, expected.path)
	}
}

func TestSetupRouterGroup_GroupPrefixes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := buildTestRouter()

	routes := router.Routes()

	projectRoutes := 0
	for _, route := range routes {
		if len(route.Path) >= 9 && route.Path[:9] == "/projects" {
			projectRoutes++
		}
	}

	assert.Greater(t, projectRoutes, 0, "Should have routes under /projects prefix")
}
