// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package file

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentifyPackageDoesNotCollapseNamespaces(t *testing.T) {
	first := IdentifyPackage("log", "1.0", "pkg:npm/%40first/log@1.0")
	second := IdentifyPackage("log", "1.0", "pkg:npm/%40second/log@1.0")
	pypi := IdentifyPackage("Django_App", "1.0", "pkg:pypi/django-app@1.0")
	assert.Equal(t, PackageVersion{Ecosystem: "npm", Name: "@first/log", Version: "1.0"}, first)
	assert.NotEqual(t, first, second)
	assert.Equal(t, PackageVersion{Ecosystem: "PyPI", Name: "django-app", Version: "1.0"}, pypi)
	assert.Empty(t, IdentifyPackage("local", "1.0", ""))
}

func TestObserveOSVRetryAndQueryCoverage(t *testing.T) {
	const locator = "https://api.osv.dev/v1/querybatch"
	const request = `{"queries":[{"version":"1.0","package":{"name":"@fixture/item","ecosystem":"npm"}}]}`
	fixture := &osvReplySequence{
		replies: []struct {
			status int
			body   string
		}{
			{http.StatusServiceUnavailable, "upstream detail"},
			{http.StatusOK, `{"results":[{}]}`},
			{http.StatusOK, `{"results":[]}`},
		},
	}
	transport := &scanTransport{base: fixture, seen: make(map[osvRequest]osvResponse)}
	check := func() (*http.Response, error) {
		r, err := http.NewRequest(http.MethodPost, locator, strings.NewReader(request))
		require.NoError(t, err)
		return transport.RoundTrip(r)
	}
	response, err := check()
	require.NoError(t, err)
	errBody, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Empty(t, errBody)
	require.NoError(t, response.Body.Close())
	_, err = transport.observation()
	require.ErrorContains(t, err, "HTTP 503")

	response, err = check()
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	observation, err := transport.observation()
	require.NoError(t, err)
	require.NotEmpty(t, observation.CompletedAt)
	require.Contains(t, observation.Packages, PackageVersion{Ecosystem: "npm", Name: "@fixture/item", Version: "1.0"})

	_, err = check()
	require.ErrorContains(t, err, "incomplete or invalid OSV batch response")
	_, err = transport.observation()
	require.ErrorContains(t, err, "incomplete or invalid OSV batch response")
}

type osvReplySequence struct {
	replies []struct {
		status int
		body   string
	}
}

func (s *osvReplySequence) RoundTrip(r *http.Request) (*http.Response, error) {
	_ = r.Body.Close()
	next := s.replies[0]
	s.replies = s.replies[1:]
	return &http.Response{StatusCode: next.status, Body: io.NopCloser(strings.NewReader(next.body))}, nil
}
