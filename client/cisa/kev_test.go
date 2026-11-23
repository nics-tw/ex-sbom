//go:build unit

package cisa

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFetchCatalog(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"valid", 200, `{"catalogVersion":"2026.11.23","count":1,"vulnerabilities":[{"cveID":"CVE-2024-45590"}]}`},
		{"unavailable", 503, `{}`},
		{"truncated", 200, `{"catalogVersion":"2026.11.23","count":2,"vulnerabilities":[{"cveID":"CVE-2024-45590"}]}`},
		{"duplicate", 200, `{"catalogVersion":"2026.11.23","count":2,"vulnerabilities":[{"cveID":"CVE-2024-45590"},{"cveID":"CVE-2024-45590"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			catalog, err := fetch(server.Client(), server.URL)
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
