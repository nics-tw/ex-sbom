// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package topology

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ex-sbom/internal/handler/middleware"
	ssbom "ex-sbom/internal/service/sbom"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() { gin.SetMode(gin.TestMode) }

const (
	testProjectID int64 = 1
	testSBOMName        = "empty"
)

// newTopologyTest builds a Handler backed by a real in-memory cache and stores
// an SBOM with no dependency levels/relations, so svc.Get returns it without a
// database. It returns a ready-to-serve gin context and its recorder.
func newTopologyTest(t *testing.T) (*Handler, *gin.Context, *httptest.ResponseRecorder) {
	t.Helper()

	cache := ssbom.NewInMemoryCache()
	cache.Set(testProjectID, testSBOMName, ssbom.FormattedSBOM{
		Components:        []string{},
		DependencyLevel:   map[int][]string{},
		Dependency:        map[string][]string{},
		ReverseDependency: map[string][]string{},
		ComponentToLevel:  map[string]int{},
		ComponentInfo:     map[string]ssbom.Component{},
	})

	h := New(ssbom.NewService(nil, cache))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.ProjectIDKey, testProjectID)
	c.Params = gin.Params{{Key: "name", Value: testSBOMName}}
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	return h, c, w
}

// TestListComponents_NoDependencyLevel verifies that an SBOM without any
// dependency levels yields an empty JSON array ([]) for data, not null, so the
// frontend's array handling does not fall into an error path.
func TestListComponents_NoDependencyLevel(t *testing.T) {
	h, c, w := newTopologyTest(t)

	h.ListComponents(c)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"data":[]`)
	assert.NotContains(t, w.Body.String(), `"data":null`)

	var resp struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotNil(t, resp.Data)
	assert.Empty(t, resp.Data)
}

// TestGetRelations_NoDependency verifies the relations endpoint also returns []
// rather than null when there are no dependencies.
func TestGetRelations_NoDependency(t *testing.T) {
	h, c, w := newTopologyTest(t)

	h.GetRelations(c)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"data":[]`)
	assert.NotContains(t, w.Body.String(), `"data":null`)
}

// TestGetComponentVulnDep_NoPaths verifies the vuln-dep endpoint always returns
// data as [] (never omitting the key or sending null) when a valid component
// has no vulnerability dependency paths, keeping the API contract consistent.
func TestGetComponentVulnDep_NoPaths(t *testing.T) {
	const comp = "libA"

	cache := ssbom.NewInMemoryCache()
	cache.Set(testProjectID, testSBOMName, ssbom.FormattedSBOM{
		Components:        []string{comp},
		DependencyLevel:   map[int][]string{0: {comp}},
		Dependency:        map[string][]string{},
		ReverseDependency: map[string][]string{},
		ComponentToLevel:  map[string]int{comp: 0},
		ComponentInfo:     map[string]ssbom.Component{comp: {Name: comp}},
	})
	h := New(ssbom.NewService(nil, cache))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(middleware.ProjectIDKey, testProjectID)
	c.Params = gin.Params{{Key: "name", Value: testSBOMName}}
	c.Request = httptest.NewRequest(http.MethodGet, "/?component="+comp, nil)

	h.GetComponentVulnDep(c)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"data":[]`)
	assert.NotContains(t, w.Body.String(), `"data":null`)
}

