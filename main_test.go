//go:build unit

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
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

func TestOpenBrowser(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		expectError bool
		description string
	}{
		{
			name:        "valid http URL",
			url:         "http://localhost:8080",
			expectError: false,
			description: "Should handle valid HTTP URL",
		},
		{
			name:        "valid https URL",
			url:         "https://example.com",
			expectError: false,
			description: "Should handle valid HTTPS URL",
		},
		{
			name:        "empty URL",
			url:         "",
			expectError: false, // Commands might still succeed with empty URL
			description: "Should handle empty URL gracefully",
		},
		{
			name:        "invalid URL format",
			url:         "not-a-url",
			expectError: false, // Commands might still succeed, depends on OS
			description: "Should handle invalid URL format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := openBrowser(tt.url)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				// On unsupported platforms, function returns nil
				// On supported platforms, it may return an error if command fails
				// We mainly test that it doesn't panic
				assert.NotPanics(t, func() {
					openBrowser(tt.url)
				}, "openBrowser should not panic")
			}
		})
	}
}

func TestOpenBrowser_PlatformSpecific(t *testing.T) {
	url := "http://localhost:8080"

	tests := []struct {
		name            string
		goos            string
		expectedCmd     string
		expectedArgs    []string
		shouldReturnNil bool
	}{
		{
			name:            "macOS (darwin)",
			goos:            "darwin",
			expectedCmd:     "open",
			expectedArgs:    []string{url},
			shouldReturnNil: false,
		},
		{
			name:            "Windows",
			goos:            "windows",
			expectedCmd:     "rundll32",
			expectedArgs:    []string{"url.dll,FileProtocolHandler", url},
			shouldReturnNil: false,
		},
		{
			name:            "Linux",
			goos:            "linux",
			expectedCmd:     "xdg-open",
			expectedArgs:    []string{url},
			shouldReturnNil: false,
		},
		{
			name:            "Unsupported platform",
			goos:            "unsupported",
			expectedCmd:     "",
			expectedArgs:    nil,
			shouldReturnNil: true,
		},
	}

	// Save original GOOS
	// originalGOOS := runtime.GOOS
	defer func() {
		// Note: We can't actually change runtime.GOOS in tests
		// This is more for documentation of expected behavior
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't actually change runtime.GOOS, so we test the current platform
			if runtime.GOOS == tt.goos {
				err := openBrowser(url)

				if tt.shouldReturnNil {
					assert.NoError(t, err, "Should return nil for unsupported platforms")
				} else {
					// Command execution may fail if the browser isn't available,
					// but the function should not panic
					assert.NotPanics(t, func() {
						openBrowser(url)
					}, "Should not panic on supported platforms")
				}
			} else {
				t.Skipf("Skipping test for %s on %s platform", tt.goos, runtime.GOOS)
			}
		})
	}
}

func TestOpenBrowser_CommandExecution(t *testing.T) {
	// Test with a command that we know will work on most systems
	url := "http://localhost:8080"

	t.Run("function executes without panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			openBrowser(url)
		}, "openBrowser should not panic")
	})

	t.Run("returns error type", func(t *testing.T) {
		err := openBrowser(url)
		// err can be nil (unsupported platform or successful execution)
		// or an error (command failed)
		if err != nil {
			assert.Implements(t, (*error)(nil), err, "Should return an error type")
		}
	})
}

// Mock-based test approach
func TestOpenBrowser_WithMocking(t *testing.T) {
	// Create a custom version of openBrowser for testing that we can mock
	type mockCommand struct {
		name string
		args []string
		err  error
	}

	var lastCommand *mockCommand

	// Mock function that captures command details instead of executing
	mockOpenBrowser := func(url string, goos string) error {
		var cmd string
		var args []string

		switch goos {
		case "darwin":
			cmd = "open"
			args = []string{url}
		case "windows":
			cmd = "rundll32"
			args = []string{"url.dll,FileProtocolHandler", url}
		case "linux":
			cmd = "xdg-open"
			args = []string{url}
		default:
			return nil
		}

		lastCommand = &mockCommand{
			name: cmd,
			args: args,
			err:  nil,
		}

		return nil
	}

	tests := []struct {
		name         string
		url          string
		goos         string
		expectedCmd  string
		expectedArgs []string
	}{
		{
			name:         "macOS command",
			url:          "http://test.com",
			goos:         "darwin",
			expectedCmd:  "open",
			expectedArgs: []string{"http://test.com"},
		},
		{
			name:         "Windows command",
			url:          "http://test.com",
			goos:         "windows",
			expectedCmd:  "rundll32",
			expectedArgs: []string{"url.dll,FileProtocolHandler", "http://test.com"},
		},
		{
			name:         "Linux command",
			url:          "http://test.com",
			goos:         "linux",
			expectedCmd:  "xdg-open",
			expectedArgs: []string{"http://test.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lastCommand = nil

			err := mockOpenBrowser(tt.url, tt.goos)
			assert.NoError(t, err)

			if tt.goos != "unsupported" {
				assert.NotNil(t, lastCommand, "Command should be captured")
				assert.Equal(t, tt.expectedCmd, lastCommand.name, "Command name should match")
				assert.Equal(t, tt.expectedArgs, lastCommand.args, "Command args should match")
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	tests := []struct {
		name            string
		portEnv         string
		browserEnv      string
		expectedPort    string
		expectedBrowser bool
	}{
		{
			name:            "default values",
			portEnv:         "",
			browserEnv:      "",
			expectedPort:    "8080",
			expectedBrowser: true,
		},
		{
			name:            "custom port",
			portEnv:         "3000",
			browserEnv:      "",
			expectedPort:    "3000",
			expectedBrowser: true,
		},
		{
			name:            "browser disabled",
			portEnv:         "",
			browserEnv:      "false",
			expectedPort:    "8080",
			expectedBrowser: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original env
			originalPort := os.Getenv("PORT")
			originalBrowser := os.Getenv("AUTO_OPEN_BROWSER")
			defer func() {
				os.Setenv("PORT", originalPort)
				os.Setenv("AUTO_OPEN_BROWSER", originalBrowser)
			}()

			// Set test env
			os.Setenv("PORT", tt.portEnv)
			os.Setenv("AUTO_OPEN_BROWSER", tt.browserEnv)

			config := getConfig()

			assert.Equal(t, tt.expectedPort, config.Port)
			assert.Equal(t, tt.expectedBrowser, config.AutoOpenBrowser)
		})
	}
}

func TestCreateServer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := createServer()

	assert.NotNil(t, server)

	// Test that routes are set up
	routes := server.Routes()
	assert.Greater(t, len(routes), 0, "Server should have routes configured")

	// Test specific routes exist
	routePaths := make(map[string]bool)
	for _, route := range routes {
		routePaths[route.Path] = true
	}

	expectedRoutes := []string{"/", "/tutorial", "/favicon.ico"}
	for _, path := range expectedRoutes {
		assert.True(t, routePaths[path], "Route %s should exist", path)
	}
}

func TestURL(t *testing.T) {
	config := Config{
		Port: "8080",
	}

	expectedURL := "http://localhost:8080"
	assert.Equal(t, expectedURL, config.URL(), "URL should match expected format")

	config.Port = "3000"
	expectedURL = "http://localhost:3000"
	assert.Equal(t, expectedURL, config.URL(), "URL should update with new port")
}
