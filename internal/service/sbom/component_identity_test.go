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
		name, raw, secondVersion string
	}{
		{
			name: "CycloneDX nested component",
			raw: `{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,
				"components":[{"type":"library","bom-ref":"first","name":"fixture","version":"1.0.0",
					"purl":"pkg:npm/fixture@1.0.0",
					"components":[{"type":"library","bom-ref":"second","name":"fixture","version":"2.0.0",
						"purl":"pkg:npm/fixture@2.0.0"}]}],
				"dependencies":[{"ref":"first","dependsOn":["second"]}]}`,
			secondVersion: "2.0.0",
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
			secondVersion: "2.0.0",
		},
	}
	placeholder := tests[0]
	placeholder.name += " with placeholder version"
	placeholder.raw = strings.Replace(placeholder.raw, `"version":"2.0.0"`, `"version":"NOASSERTION"`, 1)
	placeholder.secondVersion = "NOASSERTION"
	tests = append(tests, placeholder)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const secondKey = "fixture (second)"
			bom, _, _, err := (&Service{}).Preview([]byte(tt.raw))
			require.NoError(t, err)
			require.Equal(t, QueryCompleted, bom.ReportSource.Status)
			require.Equal(t, []string{"fixture (first)", secondKey}, bom.Components)
			require.Empty(t, bom.ComponentInfo["fixture (first)"].Vulns)
			require.True(t, bom.ComponentInfo["fixture (first)"].ContainsVulnDep)
			affected := bom.ComponentInfo[secondKey]
			require.Equal(t, "fixture", affected.Name)
			require.Equal(t, tt.secondVersion, affected.Version)
			require.Equal(t, "2.0.0", affected.ConfirmedInstalledVersion())
			require.Len(t, affected.Vulns, 1)
			require.Equal(t, "TEST-1", affected.Vulns[0].ID)
			require.Equal(t, []string{secondKey}, bom.Dependency["fixture (first)"])
		})
	}
}

func TestPreviewPreservesPURLVersionForRemediation(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = sameNameOSVFixture{}

	tests := map[string]string{
		"CycloneDX": `{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,
			"components":[{"type":"library","bom-ref":"fixture","name":"fixture","purl":"pkg:npm/fixture@2.0.0"}]}`,
		"SPDX": `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"fixture",
			"dataLicense":"CC0-1.0","documentNamespace":"https://example.org/fixture",
			"creationInfo":{"created":"2025-01-01T00:00:00Z","creators":["Tool: fixture"]},
			"packages":[{"SPDXID":"SPDXRef-fixture","name":"fixture","externalRefs":[
				{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/fixture@2.0.0"}]}]}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			bom, _, _, err := (&Service{}).Preview([]byte(raw))
			require.NoError(t, err)
			require.Equal(t, QueryCompleted, bom.ReportSource.Status)
			require.Equal(t, []string{"fixture"}, bom.Components)
			component := bom.ComponentInfo["fixture"]
			require.Len(t, component.Vulns, 1)
			require.Equal(t, "TEST-1", component.Vulns[0].ID)
			require.Equal(t, "2.0.0", component.Version)

			finding := &component.Vulns[0]
			finding.CVEIDs = []string{"CVE-2025-99999"}
			finding.KEV = KEVListed
			finding.KEVCVEs = finding.CVEIDs
			bom.ComponentInfo["fixture"] = component
			tasks := bom.RemediationAssessments(nil)
			require.Len(t, tasks, 1)
			require.Equal(t, RemediationUrgent, tasks[0].Driver.Priority)
			require.Equal(t, "2.0.0", tasks[0].Version)
		})
	}
}

func TestRemediationDistinguishesConfirmedVersionFromDisplay(t *testing.T) {
	const cve = "CVE-2025-99999"
	finding := Vuln{
		ID: cve, CVEIDs: []string{cve}, KEV: KEVListed, KEVCVE: cve,
		RepairEvidence: &RepairEvidence{
			AdvisoryID: cve, Ecosystem: "npm", Package: "fixture", Installed: "2.0.0",
			Ranges: []RepairInterval{{Start: "0", Fixed: "2.0.1"}},
		},
	}
	for _, display := range []string{"", " ", "NOASSERTION", "NONE", "2.0.0"} {
		t.Run(display, func(t *testing.T) {
			bom := FormattedSBOM{ComponentInfo: map[string]Component{
				"fixture": {Name: "fixture", Version: display, Vulns: []Vuln{finding}},
			}}
			entry := bom.RemediationAssessments(nil)[0]
			require.Equal(t, RemediationElevated, entry.Driver.Priority)
			require.True(t, entry.Driver.KEVMatch)
			require.Equal(t, []string{cve}, entry.KEVCVEs)
			require.True(t, entry.KEVVersionPending)
			require.Empty(t, entry.UrgentCVEs)
			require.Empty(t, entry.Upgrade)
			require.Zero(t, entry.Covered)
		})
	}
	bom := FormattedSBOM{ComponentInfo: map[string]Component{
		"fixture": {
			Name: "fixture", Version: "NOASSERTION", Vulns: []Vuln{finding},
			InstalledVersion: confirmedVersion("npm", "fixture", "2.0.0"),
		},
	}}
	entry := bom.RemediationAssessments(nil)[0]
	require.Equal(t, RemediationUrgent, entry.Driver.Priority)
	require.False(t, entry.KEVVersionPending)
	require.Equal(t, []string{cve}, entry.KEVCVEs)
	require.Equal(t, []string{cve}, entry.UrgentCVEs)
	require.Equal(t, "2.0.1", entry.Upgrade)
	require.Equal(t, 1, entry.Covered)

	// Previously saved reports can contain a confirmation for a version range.
	bom.ComponentInfo["fixture"].InstalledVersion.Version = "2.*"
	entry = bom.RemediationAssessments(nil)[0]
	require.Equal(t, RemediationElevated, entry.Driver.Priority)
	require.True(t, entry.KEVVersionPending)
	require.Empty(t, entry.UrgentCVEs)
	require.Zero(t, entry.Covered)
}

func TestCycloneDXPreviewRetainsKEVVersionConflict(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = sameNameOSVFixture{}
	for _, tc := range []struct {
		purlVersion string
		want        string
	}{
		{"2.0.0", "2.0.0"},
		{"v2.0.0", "2.0.0"},
		{"2.0.0+other", ""},
		{"1.0.0", ""},
	} {
		t.Run(tc.purlVersion, func(t *testing.T) {
			raw := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,
				"components":[{"type":"library","bom-ref":"fixture","name":"fixture",
				"version":"2.0.0","purl":%q}]}`, "pkg:npm/fixture@"+tc.purlVersion)
			bom, _, _, err := (&Service{}).Preview([]byte(raw))
			require.NoError(t, err)
			component := bom.ComponentInfo["fixture"]
			require.Len(t, component.Vulns, 1)
			require.Equal(t, tc.want, component.ConfirmedInstalledVersion())
		})
	}
}

func TestSPDXPreviewInstalledVersionEvidence(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = sameNameOSVFixture{}
	const goToolchain = "pkg:golang/go@"
	const npm = "pkg:npm/fixture@"
	const pypi = "pkg:pypi/fixture@"
	for _, tc := range []struct {
		name, declared, first, last, scannedVersion string
		confirmed                                   bool
	}{
		{"conflicting declaration", "1.0.0", "", npm + "2.0.0", "2.0.0", false},
		{"placeholder declaration", "NOASSERTION", "", npm + "2.0.0", "2.0.0", true},
		{"matching declaration", "2.0.0", "", npm + "2.0.0", "2.0.0", true},
		{"equivalent locators", "NOASSERTION", npm + "v2.0.0", npm + "2.0.0", "2.0.0", true},
		{"equivalent locators reversed", "NOASSERTION", npm + "2.0.0", npm + "v2.0.0", "v2.0.0", true},
		{"conflicting locator version", "NOASSERTION", npm + "3.0.0", npm + "2.0.0", "2.0.0", false},
		{"conflicting locator version reversed", "NOASSERTION", npm + "2.0.0", npm + "3.0.0", "3.0.0", false},
		{"conflicting locator name", "NOASSERTION", "pkg:npm/other", npm + "2.0.0", "2.0.0", false},
		{"conflicting locator ecosystem", "NOASSERTION", pypi + "2.0.0", npm + "2.0.0", "2.0.0", false},
		{"unversioned matching locator", "NOASSERTION", "pkg:npm/fixture", npm + "2.0.0", "2.0.0", true},
		{"equivalent PyPI version", "v2.0", "", pypi + "2.0.0", "2.0.0", true},
		{"conflicting PyPI local version", "2.0.0.post1+other", "", pypi + "2.0.0.post1+vendor", "2.0.0.post1+vendor", false},
		{"wildcard npm version", "NOASSERTION", "", npm + "2.*", "2.*", false},
		{"partial npm version", "NOASSERTION", "", npm + "2.0", "2.0", false},
		{"Go toolchain version", "NOASSERTION", "", goToolchain + "go1.24.1", "go1.24.1", true},
		{"wildcard PyPI version", "NOASSERTION", "", pypi + "2.*", "2.*", false},
		{"unbounded PyPI version", "NOASSERTION", "", pypi + "2.%E2%88%9E", "2.∞", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const purlRef = `{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":%q}`
			refs := fmt.Sprintf(purlRef, tc.last)
			if tc.first != "" {
				refs = fmt.Sprintf(purlRef, tc.first) + "," + refs
			}
			raw := fmt.Sprintf(`{
				"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"fixture",
				"dataLicense":"CC0-1.0","documentNamespace":"https://example.org/fixture",
				"creationInfo":{"created":"2025-01-01T00:00:00Z","creators":["Tool: fixture"]},
				"packages":[{"SPDXID":"SPDXRef-fixture","name":"fixture","versionInfo":%q,
					"externalRefs":[%s]}]
			}`, tc.declared, refs)
			bom, _, _, err := (&Service{}).Preview([]byte(raw))
			require.NoError(t, err)
			require.Equal(t, QueryCompleted, bom.ReportSource.Status)
			component := bom.ComponentInfo["fixture"]
			require.Equal(t, tc.declared, component.Version)
			require.Len(t, component.Vulns, 1)
			require.NotNil(t, component.InstalledVersion)
			require.Equal(t, tc.scannedVersion, component.InstalledVersion.Version)
			require.Equal(t, tc.confirmed, component.InstalledVersion.Confirmed)
			const cve = "CVE-2025-99999"
			finding := &component.Vulns[0]
			finding.CVEIDs, finding.KEV, finding.KEVCVE = []string{cve}, KEVListed, cve
			entry := bom.RemediationAssessments(nil)[0]
			require.Equal(t, []string{cve}, entry.KEVCVEs)
			if tc.confirmed {
				require.Equal(t, RemediationUrgent, entry.Driver.Priority)
				require.Equal(t, []string{cve}, entry.UrgentCVEs)
			} else {
				require.Equal(t, RemediationElevated, entry.Driver.Priority)
				require.True(t, entry.KEVVersionPending)
				require.Empty(t, entry.UrgentCVEs)
				require.Zero(t, entry.Covered)
			}
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
			case "2.0.0", "v2.0.0", "3.0.0", "2.0.0.post1+vendor", "2.*", "2.0", "2.∞", "go1.24.1":
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
