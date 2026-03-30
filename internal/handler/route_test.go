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
	wshandler "ex-sbom/internal/handler/workspace"
	ssbom "ex-sbom/internal/service/sbom"
	wsvc "ex-sbom/internal/service/workspace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// noopRepository is a stub that satisfies repository.Repository with safe no-ops.
type noopRepository struct{}

func (r *noopRepository) CreateWorkspace(_ domain.WorkspaceName) (domain.WorkspaceID, error) {
	return 1, nil
}
func (r *noopRepository) UpdateWorkspaceName(_ domain.WorkspaceID, _ domain.WorkspaceName) error {
	return nil
}
func (r *noopRepository) SoftDeleteWorkspace(_ domain.WorkspaceID) error { return nil }
func (r *noopRepository) GetWorkspaces() ([]domain.WorkspaceInfo, error) {
	return []domain.WorkspaceInfo{}, nil
}
func (r *noopRepository) Save(_ domain.WorkspaceID, _ domain.Filename, _ any, _ time.Time, _ string) error {
	return nil
}
func (r *noopRepository) SoftDeleteSBOM(_ domain.WorkspaceID, _ domain.Filename) error { return nil }
func (r *noopRepository) GetLatestAll() (domain.WorkspaceID, []domain.SBOMEntry, error) {
	return 0, nil, nil
}
func (r *noopRepository) GetLatestByWorkspace(_ domain.WorkspaceID) ([]domain.SBOMEntry, error) {
	return nil, nil
}

// buildTestRouter constructs a router with all handlers wired using a no-op repository.
func buildTestRouter() *gin.Engine {
	repo := &noopRepository{}
	cache := ssbom.NewInMemoryCache()
	sbomSvc := ssbom.NewService(repo, cache)
	workspaceSvc := wsvc.New(repo, cache)

	workspaceH := wshandler.New(workspaceSvc)
	sbomH := sbomhandler.New(sbomSvc, workspaceSvc)
	topoH := topohandler.New(sbomSvc)
	reportH := reporthandler.New(sbomSvc)

	router := gin.New()
	SetupRouterGroup(router, workspaceH, sbomH, topoH, reportH)
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
			name:           "list workspaces",
			method:         "GET",
			path:           "/workspaces",
			expectedStatus: http.StatusOK,
			description:    "Should route to workspace.List handler",
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
		{"GET", "/workspaces"},
		{"POST", "/workspaces"},
		{"GET", "/workspaces/:id"},
		{"PUT", "/workspaces/:id"},
		{"DELETE", "/workspaces/:id"},
		{"GET", "/workspaces/:id/diff"},
		{"GET", "/workspaces/:id/search"},
		{"GET", "/workspaces/:id/sboms"},
		{"POST", "/workspaces/:id/sboms"},
		{"DELETE", "/workspaces/:id/sboms/:name"},
		{"GET", "/workspaces/:id/sboms/:name/report"},
		{"GET", "/workspaces/:id/sboms/:name/topology"},
		{"GET", "/workspaces/:id/sboms/:name/topology/relations"},
		{"GET", "/workspaces/:id/sboms/:name/topology/component"},
		{"GET", "/workspaces/:id/sboms/:name/topology/component/vuln-dep"},
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

	workspaceRoutes := 0
	for _, route := range routes {
		if len(route.Path) >= 11 && route.Path[:11] == "/workspaces" {
			workspaceRoutes++
		}
	}

	assert.Greater(t, workspaceRoutes, 0, "Should have routes under /workspaces prefix")
}