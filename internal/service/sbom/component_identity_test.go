// SPDX-License-Identifier: MIT
//go:build unit

package ssbom

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreviewRetainsFindingsForSameNamePackages(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = sameNameOSVFixture{}

	tests := []struct {
		name, raw, secondKey string
	}{
		{
			name: "CycloneDX nested component",
			raw: `{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,
				"components":[{"type":"library","bom-ref":"first","name":"fixture","version":"1.0.0",
					"purl":"pkg:npm/fixture@1.0.0",
					"components":[{"type":"library","bom-ref":"second","name":"fixture","version":"2.0.0",
						"purl":"pkg:npm/fixture@2.0.0"}]}],
				"dependencies":[{"ref":"first","dependsOn":["second"]}]}`,
			secondKey: "fixture (second)",
		},
		{
			name: "SPDX",
			raw: `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"fixture",
				"dataLicense":"CC0-1.0","documentNamespace":"https://example.org/fixture",
				"creationInfo":{"created":"2025-01-01T00:00:00Z","creators":["Tool: fixture"]},
				"packages":[
					{"SPDXID":"SPDXRef-first","name":"fixture","versionInfo":"1.0.0","externalRefs":[
						{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/fixture@1.0.0"}]},
					{"SPDXID":"SPDXRef-second","name":"fixture","versionInfo":"2.0.0","externalRefs":[
						{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/fixture@2.0.0"}]}],
				"relationships":[{"spdxElementId":"SPDXRef-first","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-second"}]}`,
			secondKey: "fixture (second)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bom, _, _, err := (&Service{}).Preview([]byte(tt.raw))
			require.NoError(t, err)
			require.Equal(t, QueryCompleted, bom.ReportSource.Status)
			require.Equal(t, []string{"fixture (first)", tt.secondKey}, bom.Components)
			require.Empty(t, bom.ComponentInfo["fixture (first)"].Vulns)
			require.True(t, bom.ComponentInfo["fixture (first)"].ContainsVulnDep)
			affected := bom.ComponentInfo[tt.secondKey]
			require.Equal(t, "fixture", affected.Name)
			require.Equal(t, "2.0.0", affected.Version)
			require.Len(t, affected.Vulns, 1)
			require.Equal(t, "TEST-1", affected.Vulns[0].ID)
			require.Equal(t, []string{tt.secondKey}, bom.Dependency["fixture (first)"])
		})
	}
}

func TestDiffSBOMsWhenSameNamePackageIsAddedOrRemoved(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = sameNameOSVFixture{}

	const header = `{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[`
	const survivor = `{"type":"library","bom-ref":"first","name":"fixture","version":"1.0.0","purl":"pkg:npm/fixture@1.0.0"}`
	const extra = `{"type":"library","bom-ref":"second","name":"fixture","version":"2.0.0","purl":"pkg:npm/fixture@2.0.0"}`
	service := &Service{}
	single, checksum, _, err := service.Preview([]byte(header + survivor + `]}`))
	require.NoError(t, err)
	double, _, _, err := service.Preview([]byte(header + extra + "," + survivor + `]}`))
	require.NoError(t, err)
	require.Equal(t, []string{"fixture"}, single.Components)
	require.Equal(t, []string{"fixture (first)", "fixture (second)"}, double.Components)

	added := DiffSBOMs(single, double)
	require.Len(t, added.ByLevel, 1)
	addedLevel := added.ByLevel[double.ComponentToLevel["fixture (second)"]]
	require.Len(t, addedLevel.Added, 1)
	require.Equal(t, "fixture (second)", addedLevel.Added[0].Name)
	require.Empty(t, addedLevel.Removed)
	require.Empty(t, addedLevel.Changed)

	removed := DiffSBOMs(double, single)
	require.Len(t, removed.ByLevel, 1)
	removedLevel := removed.ByLevel[double.ComponentToLevel["fixture (second)"]]
	require.Len(t, removedLevel.Removed, 1)
	require.Equal(t, "fixture (second)", removedLevel.Removed[0].Name)
	require.Empty(t, removedLevel.Added)
	require.Empty(t, removedLevel.Changed)
	require.Equal(t, checksum, HashSBOM(single))
}

type sameNameOSVFixture struct{}

func (sameNameOSVFixture) RoundTrip(r *http.Request) (*http.Response, error) {
	var body string
	switch r.URL.String() {
	case "https://api.osv.dev/v1/querybatch":
		defer r.Body.Close()
		var batch struct {
			Queries []struct{ Version string }
		}
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			return nil, err
		}
		results := make([]string, 0, len(batch.Queries))
		for _, query := range batch.Queries {
			switch query.Version {
			case "1.0.0":
				results = append(results, `{}`)
			case "2.0.0":
				results = append(results, `{"vulns":[{"id":"TEST-1"}]}`)
			default:
				return nil, fmt.Errorf("unexpected package version: %s", query.Version)
			}
		}
		body = `{"results":[` + strings.Join(results, ",") + `]}`
	case "https://api.osv.dev/v1/vulns/TEST-1":
		body = `{"id":"TEST-1","summary":"Synthetic finding","modified":"2025-01-01T00:00:00Z"}`
	default:
		return nil, fmt.Errorf("unexpected outbound request: %s", r.URL)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
}
