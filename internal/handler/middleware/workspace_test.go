// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() { gin.SetMode(gin.TestMode) }

// newTestContext returns a gin.Context backed by a recorder, without running
// any middleware, so tests can control exactly what is stored in the context.
func newTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	return c, w
}

func TestGetProjectID_Valid(t *testing.T) {
	c, w := newTestContext()
	c.Set(ProjectIDKey, int64(5))

	id, ok := GetProjectID(c)

	assert.True(t, ok)
	assert.Equal(t, int64(5), id)
	assert.False(t, c.IsAborted())
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetProjectID_MissingKey(t *testing.T) {
	c, w := newTestContext() // nothing stored → simulates a missing ProjectID middleware

	id, ok := GetProjectID(c)

	assert.False(t, ok)
	assert.Equal(t, int64(0), id)
	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetProjectID_WrongType(t *testing.T) {
	c, w := newTestContext()
	c.Set(ProjectIDKey, "not-an-int64") // wrong type

	id, ok := GetProjectID(c)

	assert.False(t, ok)
	assert.Equal(t, int64(0), id)
	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestProjectID_Middleware verifies the middleware parses a valid :id, and
// aborts with 400 for invalid or zero ids.
func TestProjectID_Middleware(t *testing.T) {
	tests := []struct {
		name       string
		param      string
		wantStatus int
		wantID     int64
		wantSet    bool
	}{
		{"valid", "7", http.StatusOK, 7, true},
		{"non-numeric", "abc", http.StatusBadRequest, 0, false},
		{"zero", "0", http.StatusBadRequest, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router := gin.New()
			router.GET("/projects/:id", ProjectID(), func(c *gin.Context) {
				v, exists := c.Get(ProjectIDKey)
				assert.Equal(t, tt.wantSet, exists)
				if exists {
					assert.Equal(t, tt.wantID, v.(int64))
				}
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/projects/"+tt.param, nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}
