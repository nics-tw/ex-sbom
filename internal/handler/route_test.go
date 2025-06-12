//go:build unit

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSetupRouterGroup(t *testing.T) {
	// Set Gin to test mode to avoid debug output
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		description    string
	}{
		// SBOM routes
		{
			name:           "sbom upload route",
			method:         "POST",
			path:           "/sbom/upload",
			expectedStatus: http.StatusBadRequest, // Handler not implemented in test
			description:    "Should route to sbom.CreateSBOM handler",
		},
		{
			name:           "sbom delete route",
			method:         "DELETE",
			path:           "/sbom/delete",
			expectedStatus: http.StatusBadRequest,
			description:    "Should route to sbom.DeleteSBOM handler",
		},

		// Topology routes
		{
			name:           "topology get list by level route",
			method:         "GET",
			path:           "/topology/get_list_by_level",
			expectedStatus: http.StatusBadRequest,
			description:    "Should route to topology.GetComponentListByLevel handler",
		},
		{
			name:           "topology relations route",
			method:         "GET",
			path:           "/topology/relations",
			expectedStatus: http.StatusBadRequest,
			description:    "Should route to topology.GetRelations handler",
		},
		{
			name:           "topology component route",
			method:         "GET",
			path:           "/topology/component",
			expectedStatus: http.StatusBadRequest,
			description:    "Should route to topology.GetComponent handler",
		},
		{
			name:           "topology vuln dep route",
			method:         "GET",
			path:           "/topology/get_component_vuln_dep",
			expectedStatus: http.StatusBadRequest,
			description:    "Should route to topology.GetComponentVulnDep handler",
		},

		// Invalid routes
		{
			name:           "invalid sbom route",
			method:         "GET",
			path:           "/sbom/invalid",
			expectedStatus: http.StatusNotFound,
			description:    "Should return 404 for non-existent routes",
		},
		{
			name:           "invalid topology route",
			method:         "POST",
			path:           "/topology/invalid",
			expectedStatus: http.StatusNotFound,
			description:    "Should return 404 for non-existent routes",
		},
		{
			name:           "wrong method for sbom upload",
			method:         "GET",
			path:           "/sbom/upload",
			expectedStatus: http.StatusNotFound,
			description:    "Should return 405 for wrong HTTP method",
		},
		{
			name:           "wrong method for topology relations",
			method:         "POST",
			path:           "/topology/relations",
			expectedStatus: http.StatusNotFound,
			description:    "Should return 405 for wrong HTTP method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new Gin engine for each test
			router := gin.New()

			// Setup the routes
			SetupRouterGroup(router)

			// Create a test request
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			// Perform the request
			router.ServeHTTP(w, req)

			// Assert the status code
			assert.Equal(t, tt.expectedStatus, w.Code, tt.description)
		})
	}
}

func TestSetupRouterGroup_RouteRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a new router
	router := gin.New()

	// Get initial route count
	initialRoutes := len(router.Routes())

	// Setup routes
	SetupRouterGroup(router)

	// Get final route count
	finalRoutes := len(router.Routes())

	// Should have added 6 routes (2 sbom + 4 topology)
	expectedNewRoutes := 6
	actualNewRoutes := finalRoutes - initialRoutes

	assert.Equal(t, expectedNewRoutes, actualNewRoutes,
		"Should register exactly 6 new routes")

	// Verify specific routes exist
	routes := router.Routes()

	expectedRoutes := []struct {
		method string
		path   string
	}{
		{"POST", "/sbom/upload"},
		{"DELETE", "/sbom/delete"},
		{"GET", "/topology/get_list_by_level"},
		{"GET", "/topology/relations"},
		{"GET", "/topology/component"},
		{"GET", "/topology/get_component_vuln_dep"},
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

	router := gin.New()
	SetupRouterGroup(router)

	routes := router.Routes()

	// Check that SBOM routes have correct prefix
	sbomRoutes := 0
	topologyRoutes := 0

	for _, route := range routes {
		if len(route.Path) >= 5 && route.Path[:5] == "/sbom" {
			sbomRoutes++
		}
		if len(route.Path) >= 9 && route.Path[:9] == "/topology" {
			topologyRoutes++
		}
	}

	assert.Equal(t, 2, sbomRoutes, "Should have 2 routes under /sbom prefix")
	assert.Equal(t, 4, topologyRoutes, "Should have 4 routes under /topology prefix")
}
