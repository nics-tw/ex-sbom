// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package file

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

func TestPackageIdentityMatchesOSVScanner(t *testing.T) {
	tests := []struct {
		label, name, version, locator string
		ecosystem, queryName          string
		spdx                          bool
	}{
		{label: "Debian CycloneDX", name: "fixture", version: "1.0", locator: "pkg:deb/debian/fixture@1.0?distro=debian-12", ecosystem: "Debian:12", queryName: "fixture"},
		{label: "Debian SPDX", name: "fixture", version: "1.0", locator: "pkg:deb/debian/fixture@1.0?distro=debian-bookworm", ecosystem: "Debian:12", queryName: "fixture", spdx: true},
		{label: "Ubuntu", name: "fixture", version: "1.0", locator: "pkg:deb/ubuntu/fixture@1.0?distro=ubuntu-jammy", ecosystem: "Ubuntu:22.04:LTS", queryName: "fixture"},
		{label: "Alpine", name: "fixture", version: "1.0-r1", locator: "pkg:apk/alpine/fixture@1.0-r1?distro=alpine-3.22", ecosystem: "Alpine:v3.22", queryName: "fixture"},
		{label: "Go subpath", name: "fixture", version: "v4.1.0", locator: "pkg:golang/example.org/org/fixture@v4.1.0#v4", ecosystem: "Go", queryName: "example.org/org/fixture/v4"},
		{label: "Go suffix in name", name: "example.org/org/fixture/v4", version: "v4.1.0", locator: "pkg:golang/example.org/org/fixture/v4@v4.1.0", ecosystem: "Go", queryName: "example.org/org/fixture/v4"},
	}

	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			expected := PackageVersion{Ecosystem: tc.ecosystem, Name: tc.queryName, Version: tc.version}
			path := filepath.Join(t.TempDir(), "fixture.cdx.json")
			data := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":%q,"version":%q,"purl":%q}]}`, tc.name, tc.version, tc.locator)
			if tc.spdx {
				path = filepath.Join(t.TempDir(), "fixture.spdx.json")
				data = fmt.Sprintf(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"fixture","dataLicense":"CC0-1.0","documentNamespace":"https://example.org/fixture","creationInfo":{"created":"2025-01-01T00:00:00Z","creators":["Tool: fixture"]},"packages":[{"SPDXID":"SPDXRef-fixture","name":%q,"versionInfo":%q,"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":%q}]}]}`, tc.name, tc.version, tc.locator)
			}
			require.NoError(t, os.WriteFile(path, []byte(data), 0600))
			http.DefaultTransport = scanFixtureTransport{expected: expected}
			findings, observation, err := GetScanResult(path)
			require.NoError(t, err)
			key := IdentifyPackage(tc.name, tc.version, tc.locator)
			assert.Equal(t, expected, key)
			assert.Contains(t, observation.Packages, key)
			require.Len(t, findings[key].Vulnerabilities, 1)
			assert.Equal(t, "TEST-1", findings[key].Vulnerabilities[0].GetId())
		})
	}
}

func TestGetScanResultRejectsInvalidOSVDetails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.cdx.json")
	data := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"fixture","version":"1.0","purl":"pkg:npm/fixture@1.0"}]}`
	require.NoError(t, os.WriteFile(path, []byte(data), 0600))
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	// The batch reports TEST-1, but its detail response contains malformed JSON.
	http.DefaultTransport = scanFixtureTransport{
		expected: PackageVersion{Ecosystem: "npm", Name: "fixture", Version: "1.0"},
		detail:   `{"id":`,
	}
	findings, observation, err := GetScanResult(path)
	require.ErrorContains(t, err, "invalid OSV vulnerability details")
	assert.Nil(t, findings)
	assert.Equal(t, QueryObservation{}, observation)
}

type scanFixtureTransport struct {
	expected PackageVersion
	detail   string
}

func (transport scanFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		defer r.Body.Close()
	}
	var reply string
	switch {
	case r.Method == http.MethodPost && r.URL.String() == "https://api.osv.dev/v1/querybatch":
		var batch struct {
			Queries []struct {
				Version string
				Package struct{ Ecosystem, Name string }
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			return nil, err
		}
		if len(batch.Queries) != 1 {
			return nil, fmt.Errorf("expected one OSV query, got %d", len(batch.Queries))
		}
		query := batch.Queries[0]
		actual := PackageVersion{Ecosystem: query.Package.Ecosystem, Name: query.Package.Name, Version: query.Version}
		if actual != transport.expected {
			return nil, fmt.Errorf("OSV query identity = %+v, want %+v", actual, transport.expected)
		}
		reply = `{"results":[{"vulns":[{"id":"TEST-1"}]}]}`
	case r.Method == http.MethodGet && r.URL.String() == "https://api.osv.dev/v1/vulns/TEST-1":
		reply = transport.detail
		if reply == "" {
			reply = `{"id":"TEST-1","summary":"Synthetic finding","modified":"2025-01-01T00:00:00Z"}`
		}
	default:
		return nil, fmt.Errorf("unexpected outbound request: %s %s", r.Method, r.URL)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(reply)), Header: http.Header{}}, nil
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
