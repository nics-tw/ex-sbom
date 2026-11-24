// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package sbom

import (
	"bytes"
	"ex-sbom/internal/domain"
	"ex-sbom/internal/handler/middleware"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"
	"ex-sbom/util/msg"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// missingProjectRepo embeds repository.Repository so only ProjectExists needs
// a real implementation; any other call (e.g. the insert) would panic, proving
// a missing project is rejected before anything is written.
type missingProjectRepo struct {
	repository.Repository
}

func (missingProjectRepo) ProjectExists(_ domain.ProjectID) (bool, error) { return false, nil }

func TestCreateOnMissingProjectReturns404(t *testing.T) {
	gin.SetMode(gin.TestMode)

	svc := ssbom.NewService(missingProjectRepo{}, ssbom.NewInMemoryCache())
	h := New(svc, nil)

	router := gin.New()
	router.POST("/sboms", func(c *gin.Context) {
		c.Set(middleware.ProjectIDKey, int64(999))
		h.Create(c)
	})

	token, err := h.previewToken(999, "any", time.Time{}, nil)
	assert.NoError(t, err)
	body := bytes.NewBufferString(fmt.Sprintf(`{"version":"v1","bom_result":{},"sha256":"any","preview_token":%q}`, token))
	req := httptest.NewRequest(http.MethodPost, "/sboms", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), msg.ErrProjectNotFound)
}

func TestPreviewTokenBinding(t *testing.T) {
	h := New(nil, nil)
	timestamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	token, err := h.previewToken(7, "checksum", timestamp, nil)
	assert.NoError(t, err)
	assert.True(t, h.validPreviewToken(token, 7, "checksum", timestamp, nil))
	assert.False(t, h.validPreviewToken(token, 8, "checksum", timestamp, nil))
	assert.False(t, h.validPreviewToken(token, 7, "changed", timestamp, nil))
	assert.False(t, h.validPreviewToken(token, 7, "checksum", timestamp.Add(time.Second), nil))
	assert.False(t, h.validPreviewToken("invalid", 7, "checksum", timestamp, nil))
}

func TestCreateRejectsMissingOrInvalidPreviewToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := New(ssbom.NewService(missingProjectRepo{}, ssbom.NewInMemoryCache()), nil)
	otherProjectToken, err := h.previewToken(2, "any", time.Time{}, nil)
	assert.NoError(t, err)
	router := gin.New()
	router.POST("/sboms", func(c *gin.Context) {
		c.Set(middleware.ProjectIDKey, int64(1))
		h.Create(c)
	})
	for _, token := range []string{"", "invalid", otherProjectToken} {
		body := fmt.Sprintf(`{"version":"v1","bom_result":{},"sha256":"any","preview_token":%q}`, token)
		req := httptest.NewRequest(http.MethodPost, "/sboms", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid preview token")
	}
}

func TestPreviewTokenBindsReportSource(t *testing.T) {
	h := New(nil, nil)
	source := &ssbom.ReportSource{FileName: "input.json", FileSHA256: "source hash", Status: ssbom.QueryCompleted, LEVArchiveStatus: ssbom.LEVArchiveDisabled}
	token, err := h.previewToken(1, "analysis hash", time.Time{}, source)
	assert.NoError(t, err)
	assert.True(t, h.validPreviewToken(token, 1, "analysis hash", time.Time{}, source))
	assert.False(t, h.validPreviewToken(token, 1, "analysis hash", time.Time{}, nil))
	withGoIdentity := *source
	withGoIdentity.GoComponents = map[string]bool{"go-module": true}
	assert.False(t, h.validPreviewToken(token, 1, "analysis hash", time.Time{}, &withGoIdentity))

	changed := *source
	changed.FileSHA256 = "other hash"
	assert.False(t, h.validPreviewToken(token, 1, "analysis hash", time.Time{}, &changed))
	changed = *source
	changed.Status = ssbom.QueryPartial
	assert.False(t, h.validPreviewToken(token, 1, "analysis hash", time.Time{}, &changed))
	changed = *source
	changed.LEVArchiveStatus = ssbom.LEVArchiveConfigured
	assert.False(t, h.validPreviewToken(token, 1, "analysis hash", time.Time{}, &changed))
}
