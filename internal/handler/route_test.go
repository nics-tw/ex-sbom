// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"ex-sbom/internal/domain"
	reporthandler "ex-sbom/internal/handler/report"
	sbomhandler "ex-sbom/internal/handler/sbom"
	topohandler "ex-sbom/internal/handler/topology"
	projecthandler "ex-sbom/internal/handler/workspace"
	"ex-sbom/internal/repository"
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
func (r *noopRepository) ProjectExists(id domain.ProjectID) (bool, error) { return id == 1, nil }
func (r *noopRepository) CreateSBOM(_ domain.ProjectID, _ domain.Version, _ any, _ time.Time, _ string) error {
	return nil
}
func (r *noopRepository) DeleteSBOM(_ domain.ProjectID, _ domain.Version) error { return nil }
func (r *noopRepository) GetLatestAll() (domain.ProjectID, []domain.SBOMEntry, error) {
	return 0, nil, nil
}
func (r *noopRepository) GetAllByProject(_ domain.ProjectID) ([]domain.SBOMEntry, error) {
	return nil, nil
}
func (r *noopRepository) GetAllVersions(_ domain.ProjectID) ([]domain.VersionInfo, error) {
	return nil, nil
}
func (r *noopRepository) RenameVersion(_ domain.ProjectID, _, _ domain.Version) error {
	return nil
}
func (r *noopRepository) FindVersionBySHA256(_ domain.ProjectID, _ domain.SHA256) (domain.Version, error) {
	return "", repository.ErrVersionNotFound
}

// buildTestRouter constructs a router with all handlers wired using a no-op repository.
func buildTestRouter() *gin.Engine {
	repo := &noopRepository{}
	cache := ssbom.NewInMemoryCache()
	for _, name := range []string{"release/1.2", "release%2F1.2", "release+ candidate/1.2"} {
		cache.Set(1, name, ssbom.FormattedSBOM{DependencyLevel: map[int][]string{0: {name}}})
	}
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

func TestSetupRouterGroup_RejectsMissingProjectBeforeDispatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := buildTestRouter()
	for _, tc := range []struct{ method, route string }{
		{http.MethodGet, "/projects/2/versions"},
		{http.MethodGet, "/projects/2/sboms/release/report"},
		{http.MethodGet, "/projects/2/sboms"},
		{http.MethodGet, "/projects/2/search?q=test"},
		{http.MethodPost, "/projects/2/sboms/preview"},
	} {
		t.Run(tc.route, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(tc.method, tc.route, nil))
			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.JSONEq(t, `{"error":"Project not found"}`, w.Body.String())
		})
	}
}

func TestSetupRouterGroup_RejectsCrossSitePDFDownload(t *testing.T) {
	router := buildTestRouter()
	req := httptest.NewRequest(http.MethodGet, "/projects/1/sboms/release/report", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestSetupRouterGroup_DecodesVersionPathOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := buildTestRouter()
	for _, name := range []string{"release/1.2", "release%2F1.2", "release+ candidate/1.2"} {
		t.Run(name, func(t *testing.T) {
			path := "/projects/1/sboms/" + url.PathEscape(name) + "/topology"
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), name)
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
