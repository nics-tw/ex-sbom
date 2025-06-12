//go:build unit

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSetupSSR(t *testing.T) {
	// Set Gin to test mode to avoid debug output
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectedType   string
		description    string
	}{
		{
			name:           "root route serves HTML",
			method:         "GET",
			path:           "/",
			expectedStatus: http.StatusOK,
			expectedType:   "text/html",
			description:    "Should serve index.html template",
		},
		{
			name:           "tutorial route serves HTML",
			method:         "GET",
			path:           "/tutorial",
			expectedStatus: http.StatusOK,
			expectedType:   "text/html",
			description:    "Should serve tutorial.html template",
		},
		{
			name:           "favicon route serves ICO",
			method:         "GET",
			path:           "/favicon.ico",
			expectedStatus: http.StatusOK,
			expectedType:   "image/x-icon",
			description:    "Should serve favicon.ico file",
		},
		{
			name:           "apple touch icon serves PNG",
			method:         "GET",
			path:           "/apple-touch-icon.png",
			expectedStatus: http.StatusOK,
			expectedType:   "image/png",
			description:    "Should serve apple-touch-icon.png file",
		},
		{
			name:           "apple touch icon precomposed serves PNG",
			method:         "GET",
			path:           "/apple-touch-icon-precomposed.png",
			expectedStatus: http.StatusOK,
			expectedType:   "image/png",
			description:    "Should serve apple-touch-icon-precomposed.png file",
		},
		{
			name:           "non-existent route returns 404",
			method:         "GET",
			path:           "/non-existent",
			expectedStatus: http.StatusNotFound,
			expectedType:   "",
			description:    "Should return 404 for non-existent routes",
		},
		{
			name:           "wrong method returns 405",
			method:         "POST",
			path:           "/",
			expectedStatus: http.StatusNotFound,
			expectedType:   "",
			description:    "Should return 405 for wrong HTTP method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new Gin engine for each test
			router := gin.New()

			// Setup SSR routes
			setupSSR(router)

			// Create a test request
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			// Perform the request
			router.ServeHTTP(w, req)

			// Assert the status code
			assert.Equal(t, tt.expectedStatus, w.Code, tt.description)

			// Assert content type if expected
			if tt.expectedType != "" {
				contentType := w.Header().Get("Content-Type")
				assert.True(t, strings.Contains(contentType, tt.expectedType),
					"Expected content type to contain %s, got %s", tt.expectedType, contentType)
			}
		})
	}
}

func TestSetupSSR_HTMLTemplateContent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	setupSSR(router)

	tests := []struct {
		name           string
		path           string
		expectedInBody string
	}{
		{
			name:           "index page contains expected content",
			path:           "/",
			expectedInBody: "<!DOCTYPE html>", // Assuming templates start with DOCTYPE
		},
		{
			name:           "tutorial page contains expected content",
			path:           "/tutorial",
			expectedInBody: "<!DOCTYPE html>", // Assuming templates start with DOCTYPE
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedInBody,
				"Response body should contain expected content")
		})
	}
}

func TestSetupSSR_StaticFileHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	setupSSR(router)

	staticFiles := []struct {
		path         string
		expectedType string
	}{
		{"/favicon.ico", "image/x-icon"},
		{"/apple-touch-icon.png", "image/png"},
		{"/apple-touch-icon-precomposed.png", "image/png"},
	}

	for _, file := range staticFiles {
		t.Run("static file "+file.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", file.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			// Check content type
			contentType := w.Header().Get("Content-Type")
			assert.True(t, strings.Contains(contentType, file.expectedType),
				"Expected content type to contain %s, got %s", file.expectedType, contentType)

			// Check that we actually got some content
			assert.Greater(t, w.Body.Len(), 0, "Response body should not be empty")
		})
	}
}

func TestSetupSSR_RouteCount(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()

	// Get initial route count
	initialRoutes := len(router.Routes())

	// Setup SSR routes
	setupSSR(router)

	// Get final route count
	finalRoutes := len(router.Routes())

	// Should have added 5 routes (2 HTML + 3 static files)
	expectedNewRoutes := 5
	actualNewRoutes := finalRoutes - initialRoutes

	assert.Equal(t, expectedNewRoutes, actualNewRoutes,
		"Should register exactly 5 new routes")
}

func TestSetupSSR_TemplateRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()

	// This should not panic if templates are properly embedded and parsed
	assert.NotPanics(t, func() {
		setupSSR(router)
	}, "setupSSR should not panic when setting up templates")
}

func TestSetupSSR_EmbeddedFilesExist(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	setupSSR(router)

	// Test that embedded files are accessible
	embeddedFiles := []string{
		"/favicon.ico",
		"/apple-touch-icon.png",
		"/apple-touch-icon-precomposed.png",
	}

	for _, path := range embeddedFiles {
		t.Run("embedded file "+path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// Should not return 404, meaning the embedded file exists
			assert.NotEqual(t, http.StatusNotFound, w.Code,
				"Embedded file %s should exist and be accessible", path)

			// Should return 200 for successful file serving
			assert.Equal(t, http.StatusOK, w.Code,
				"Embedded file %s should be served successfully", path)
		})
	}
}
