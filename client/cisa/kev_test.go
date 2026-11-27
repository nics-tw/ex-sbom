//go:build unit

package cisa

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type catalogTransport func(*http.Request) (*http.Response, error)

func (send catalogTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return send(request)
}

func TestFetchCatalog(t *testing.T) {
	const validCatalog = `{"catalogVersion":"2026.11.23","count":1,"vulnerabilities":[{"cveID":"CVE-2024-45590"}]}`
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"valid", 200, validCatalog},
		{"unavailable", 503, validCatalog},
		{"truncated", 200, `{"catalogVersion":"2026.11.23","count":2,"vulnerabilities":[{"cveID":"CVE-2024-45590"}]}`},
		{"duplicate", 200, `{"catalogVersion":"2026.11.23","count":2,"vulnerabilities":[{"cveID":"CVE-2024-45590"},{"cveID":"CVE-2024-45590"}]}`},
		{"invalid CVE", 200, `{"catalogVersion":"2026.11.23","count":1,"vulnerabilities":[{"cveID":"GHSA-1234"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: catalogTransport(func(request *http.Request) (*http.Response, error) {
				require.Equal(t, CatalogURL, request.URL.String())
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			catalog, err := Fetch(client, CatalogURL)
			if tc.name != "valid" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "2026.11.23", catalog.Version)
			require.False(t, catalog.RetrievedAt.IsZero())
			require.True(t, catalog.Contains("CVE-2024-45590"))
			require.False(t, catalog.Contains("CVE-2000-0001"))
		})
	}
}

func TestCatalogCacheKeepsLastSuccessfulCatalog(t *testing.T) {
	var cache catalogCache
	now := time.Date(2026, 11, 23, 11, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	unavailable := errors.New("catalog unavailable")
	fetches := 0
	load := func() (Catalog, error) {
		fetches++
		switch fetches {
		case 1:
			return Catalog{Version: "v1", RetrievedAt: now, entries: map[string]struct{}{"CVE-2024-45590": {}}}, nil
		case 2:
			return Catalog{}, unavailable
		default:
			return Catalog{Version: "v2", RetrievedAt: now}, nil
		}
	}
	first, err := cache.current(clock, load)
	require.NoError(t, err)
	now = now.Add(time.Hour - time.Second)
	cached, err := cache.current(clock, load)
	require.NoError(t, err)
	require.Equal(t, first, cached)
	now = now.Add(time.Second)
	stale, err := cache.current(clock, load)
	require.ErrorIs(t, err, unavailable)
	require.Equal(t, first, stale)
	require.True(t, stale.Contains("CVE-2024-45590"))
	now = now.Add(time.Minute - time.Second)
	stale, err = cache.current(clock, load)
	require.ErrorIs(t, err, unavailable)
	require.Equal(t, first, stale)
	now = now.Add(time.Second)
	current, err := cache.current(clock, load)
	require.NoError(t, err)
	require.Equal(t, "v2", current.Version)
	require.Equal(t, now, current.RetrievedAt)
}
