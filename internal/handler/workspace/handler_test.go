// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package project

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/handler/middleware"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"
	psvc "ex-sbom/internal/service/workspace"
	"ex-sbom/util/msg"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// missingProjectRepo behaves like the real repository when the requested
// project id does not exist. It embeds repository.Repository so any method
// that should not be reached for a missing project panics.
type missingProjectRepo struct {
	repository.Repository
}

func (missingProjectRepo) ProjectExists(_ domain.ProjectID) (bool, error) { return false, nil }
func (missingProjectRepo) UpdateProjectName(_ domain.ProjectID, _ domain.ProjectName) error {
	return domain.ErrProjectNotFound
}
func (missingProjectRepo) DeleteProject(_ domain.ProjectID) error {
	return domain.ErrProjectNotFound
}

func TestMissingProjectReturns404(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := New(psvc.New(missingProjectRepo{}, ssbom.NewInMemoryCache()))

	router := gin.New()
	proj := router.Group("/projects/:id")
	proj.Use(middleware.ProjectID())
	proj.GET("", h.Get)
	proj.PUT("", h.Update)
	proj.DELETE("", h.Delete)

	tests := []struct {
		name   string
		method string
		body   string
	}{
		{name: "get", method: http.MethodGet},
		{name: "rename", method: http.MethodPut, body: `{"name":"renamed"}`},
		{name: "delete", method: http.MethodDelete},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = bytes.NewBufferString(tt.body)
			}
			req := httptest.NewRequest(tt.method, "/projects/999", body)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.Contains(t, w.Body.String(), msg.ErrProjectNotFound)
		})
	}
}
