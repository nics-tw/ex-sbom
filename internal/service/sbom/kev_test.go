// SPDX-License-Identifier: MIT

//go:build unit

package ssbom

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"ex-sbom/client/cisa"
	"github.com/stretchr/testify/require"
)

type kevCatalogTransport struct{}

func TestKEVEvidenceMatchesTheFinding(t *testing.T) {
	const matching = "CVE-2025-0001"
	const unrelated = "CVE-2025-0002"
	finding := Vuln{CVEIDs: []string{matching}, KEV: KEVListed, KEVCVE: unrelated, EPSS: "0.04"}
	status, ids := finding.KEVEvidence()
	require.Equal(t, KEVUnknown, status)
	require.Empty(t, ids)
	require.InDelta(t, 0.04, finding.ExploitationSignal(status, nil).Value, 0.0001)

	finding.KEVCVEs = []string{unrelated, matching}
	status, ids = finding.KEVEvidence()
	require.Equal(t, KEVListed, status)
	require.Equal(t, []string{matching}, ids)
}

func (kevCatalogTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	const body = `{"catalogVersion":"fixture","count":1,"vulnerabilities":[{"cveID":"CVE-2025-0002"}]}`
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}

func TestApplyKEV(t *testing.T) {
	const listed = "CVE-2025-0002"
	const unlisted = "CVE-2025-0001"
	newBOM := func() FormattedSBOM {
		return FormattedSBOM{
			ReportSource: &ReportSource{},
			ComponentInfo: map[string]Component{
				"component": {Vulns: []Vuln{
					{ID: "GHSA-example", CVEIDs: []string{unlisted, listed}},
					{ID: unlisted, CVEIDs: []string{unlisted}},
					{ID: "OSV-advisory-no-cve"},
				}},
			},
		}
	}
	t.Run("no provenance", func(t *testing.T) {
		bom := newBOM()
		bom.ReportSource = nil
		applyKEV(&bom, func() (cisa.Catalog, error) {
			t.Fatal("checked KEV without report provenance")
			return cisa.Catalog{}, nil
		})
		require.Equal(t, KEVUnknown, bom.ComponentInfo["component"].Vulns[0].KEV)
	})
	t.Run("failed catalog", func(t *testing.T) {
		bom := newBOM()
		applyKEV(&bom, func() (cisa.Catalog, error) {
			return cisa.Catalog{}, errors.New("catalog unavailable")
		})
		require.Nil(t, bom.ReportSource.KEVCheckedAt)
		require.Empty(t, bom.ReportSource.KEVCatalogVersion)
		require.Equal(t, KEVUnknown, bom.ComponentInfo["component"].Vulns[0].KEV)
	})
	t.Run("partial alias match and unlisted finding", func(t *testing.T) {
		client := &http.Client{Transport: kevCatalogTransport{}}
		fetches := 0
		bom := newBOM()
		applyKEV(&bom, func() (cisa.Catalog, error) {
			fetches++
			return cisa.Fetch(client, cisa.CatalogURL)
		})
		require.Equal(t, 1, fetches)
		require.NotNil(t, bom.ReportSource.KEVCheckedAt)
		require.Equal(t, "fixture", bom.ReportSource.KEVCatalogVersion)
		findings := bom.ComponentInfo["component"].Vulns
		require.Equal(t, KEVListed, findings[0].KEV)
		require.Equal(t, []string{listed}, findings[0].KEVCVEs)
		require.Equal(t, KEVUnlisted, findings[1].KEV)
		require.Empty(t, findings[1].KEVCVEs)
		require.Equal(t, KEVUnknown, findings[2].KEV)
	})
}
