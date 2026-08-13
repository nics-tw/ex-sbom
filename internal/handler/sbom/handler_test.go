// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package sbom

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"fmt"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/handler/middleware"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"
	"ex-sbom/util/msg"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestToCreateResponse(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedMsg string
	}{
		{name: "normal version", input: "v1.0", expectedMsg: "ok"},
		{name: "empty version", input: "", expectedMsg: "ok"},
		{name: "unicode version", input: "測試版本", expectedMsg: "ok"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := []string{}
			if tt.input != "" {
				names = []string{tt.input}
			}

			result := toCreateResponse(1, names, nil)

			assert.IsType(t, gin.H{}, result)
			assert.Equal(t, tt.expectedMsg, result[msg.RespMsg])
		})
	}
}

func TestPreviewOversizedUpload(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Handler with nil services: if the oversized upload ever reached the
	// parser/scanner, the test would panic on a nil pointer dereference.
	h := New(nil, nil)

	router := gin.New()
	router.POST("/preview", func(c *gin.Context) {
		c.Set(middleware.ProjectIDKey, int64(1))
		h.Preview(c)
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", "huge.json")
	assert.NoError(t, err)

	chunk := bytes.Repeat([]byte("a"), 1<<20) // 1 MiB
	for written := int64(0); written <= MaxSBOMUploadBytes; written += int64(len(chunk)) {
		_, err := part.Write(chunk)
		assert.NoError(t, err)
	}
	assert.NoError(t, writer.Close())

	req := httptest.NewRequest(http.MethodPost, "/preview", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Contains(t, w.Body.String(), msg.ErrFileTooLarge)
}

// notFoundRepo embeds repository.Repository so only RenameVersion needs a real
// implementation; any other call would panic, proving nothing else is touched.
type notFoundRepo struct {
	repository.Repository
}

func (notFoundRepo) RenameVersion(_ domain.ProjectID, oldVersion, _ domain.Version) error {
	return fmt.Errorf("%w: %s", repository.ErrVersionNotFound, oldVersion)
}

func TestRenameDeletedVersionReturns404(t *testing.T) {
	gin.SetMode(gin.TestMode)

	svc := ssbom.NewService(notFoundRepo{}, ssbom.NewInMemoryCache())
	h := New(svc, nil)

	router := gin.New()
	router.PUT("/sboms/:name", func(c *gin.Context) {
		c.Set(middleware.ProjectIDKey, int64(1))
		h.Rename(c)
	})

	body := bytes.NewBufferString(`{"version":"v2"}`)
	req := httptest.NewRequest(http.MethodPut, "/sboms/deleted-version", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), msg.ErrSBOMNotFound)
}
