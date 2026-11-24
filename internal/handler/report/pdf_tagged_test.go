// SPDX-License-Identifier: MIT

//go:build unit && taggedpdf

package report

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ex-sbom/client/first"
	"ex-sbom/internal/handler/middleware"
	ssbom "ex-sbom/internal/service/sbom"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestTaggedReportDownloadPreservesPrioritiesAndEvidence(t *testing.T) {
	extract, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext is required to verify the report text")
	}
	inspect, err := exec.LookPath("pdfinfo")
	if err != nil {
		t.Skip("pdfinfo is required to verify the report structure")
	}

	const sourceFile = "來源-𠮷-🔒-\U0010FFFC.spdx.json"
	const componentName = "example-𠮷-🧪-\U0002EBF1"
	const covered, residual = "CVE-2099-1000", "CVE-2099-1001"
	const urgentName, elevatedName, nearBoundaryName, reviewName = "urgent[U+202E]component", "synthetic-elevated", "synthetic-near-boundary", "synthetic-review"
	checksum := strings.Repeat("0123456789abcdef", 4)
	queriedAt := time.Date(2026, 11, 23, 1, 2, 3, 0, time.UTC)
	bom := ssbom.FormattedSBOM{
		ReportSource: &ssbom.ReportSource{
			FileName:          sourceFile,
			FileSHA256:        checksum,
			Specification:     "SPDX-2.3",
			Status:            ssbom.QueryCompleted,
			QueriedAt:         &queriedAt,
			KEVCheckedAt:      &queriedAt,
			KEVCatalogVersion: "synthetic-1",
		},
		ComponentToLevel: map[string]int{"priority": 0, "urgent": 1, "elevated": 1, "review": 1},
		ComponentInfo: map[string]ssbom.Component{
			"priority": {
				Name:    componentName,
				Version: "1.0.0",
				Vulns: []ssbom.Vuln{
					{
						ID: covered, CVEIDs: []string{covered}, CVSSScore: "9.8", CVSSVersion: "3.1",
						KEV: ssbom.KEVListed, KEVCVE: covered,
						EPSS: "0.2", EPSSDate: "2026-11-22",
						LEV: "0.37", LEVMethod: first.LEVMethod,
						LEVFirst: "2026-10-24", LEVAsOf: "2026-11-22",
						RepairEvidence: &ssbom.RepairEvidence{
							AdvisoryID: covered, Ecosystem: "npm", Package: "example", Installed: "1.0.0",
							Ranges: []ssbom.RepairInterval{{Start: "0", Fixed: "1.2.3"}},
						},
					},
					{ID: residual, CVEIDs: []string{residual}, CVSSScore: "6.5", KEV: ssbom.KEVListed, KEVCVE: residual},
				},
			},
			"urgent": {
				Name: "urgent\u202Ecomponent", Version: "2.0.0",
				Vulns: []ssbom.Vuln{{
					ID: "CVE-2099-1002", CVEIDs: []string{"CVE-2099-1002"}, CVSSScore: "7.1",
					KEV: ssbom.KEVListed, KEVCVE: "CVE-2099-1002",
				}},
			},
			"elevated": {
				Name: elevatedName, Version: "2.0.0",
				Vulns: []ssbom.Vuln{{ID: "TEST-ELEVATED", CVSSScore: "8.1", EPSS: "0.1", KEV: ssbom.KEVUnlisted}},
			},
			"near-boundary": {
				Name: nearBoundaryName, Version: "2.0.0",
				Vulns: []ssbom.Vuln{{
					ID: "TEST-NEAR-BOUNDARY", CVSSScore: "8.1", EPSS: "0.09999999999999999",
					LEV: "0.01", LEVMethod: first.LEVMethod, KEV: ssbom.KEVUnlisted,
				}},
			},
			"review": {
				Name: reviewName, Version: "2.0.0",
				Vulns: []ssbom.Vuln{{ID: "TEST-REVIEW", CVSSScore: "8.1", EPSS: "0.099999", KEV: ssbom.KEVUnlisted}},
			},
		},
	}
	for i := 1; i <= 74; i++ {
		name := fmt.Sprintf("fixture-inventory-%03d", i)
		bom.ComponentInfo[name] = ssbom.Component{Name: name, Version: "1.0.0"}
	}
	cache := ssbom.NewInMemoryCache()
	cache.Set(1, "fixture", bom)
	handler := New(ssbom.NewService(reportRepository{}, cache))
	router := gin.New()
	router.GET("/projects/:id/sboms/:name/report", middleware.ProjectID(), handler.CreatePDF)

	for _, tc := range []struct {
		language, priority, version, expected, pending, remaining string
		elevated, review, lowerBound, needsReview                 string
		projected, continuationLink                               string
	}{
		{
			"en", "Update immediately", "Upgrade to test", "KEV findings expected to be addressed",
			"KEV findings without confirmed coverage in this version", "Components still requiring immediate updates",
			"Prioritize fix assessment", "Assess next", "At least", "Components with findings to assess",
			"CVEs expected to be addressed across all known affected components", "View remediation order",
		},
		{
			"zh-Hant", "立即更新", "建議驗測版本", "預計涵蓋的 KEV 弱點",
			"此版本未確認涵蓋的 KEV 弱點", "仍需立即更新的元件",
			"優先評估修補", "待評估", "至少", "有待評估弱點的元件",
			"已知受影響元件均有方案的 CVE 數", "查看修補順序表",
		},
	} {
		t.Run(tc.language, func(t *testing.T) {
			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/projects/1/sboms/fixture/report?lang="+tc.language, nil))
			require.Equal(t, http.StatusOK, resp.Code)
			require.Equal(t, tc.language, resp.Header().Get("Content-Language"))
			pdf := filepath.Join(t.TempDir(), "report.pdf")
			require.NoError(t, os.WriteFile(pdf, resp.Body.Bytes(), 0600))

			raw, err := exec.Command(extract, "-raw", pdf, "-").Output()
			require.NoError(t, err)
			home, later, ok := strings.Cut(string(raw), "\f")
			require.True(t, ok)
			home = strings.Join(strings.Fields(home), " ")
			require.Contains(t, home, "SPDX-2.3")
			require.Contains(t, home, tc.needsReview+" 1")
			require.Contains(t, home, tc.continuationLink)
			for _, part := range []string{
				tc.priority, componentName, tc.version + " 1.2.3",
				tc.expected + " " + covered, tc.pending + " " + residual,
				tc.projected + " 1", tc.remaining + " 2",
			} {
				before, rest, found := strings.Cut(home, part)
				require.Truef(t, found, "missing or out of order: %q after %q", part, before)
				home = rest
			}
			for _, part := range []string{sourceFile, checksum, "NIST CSWP 41", "max(EPSS, LEV, KEV)", covered, residual, "20%", "37%", first.LEVMethod, "2026-10-24", "fixture-inventory-074"} {
				require.Contains(t, later, part)
			}

			continuation := strings.Join(strings.Fields(later), " ")
			require.Contains(t, continuation, "2 "+urgentName+" 2.0.0 7.1")
			if tc.language == "en" {
				require.Contains(t, continuation, "verify missing inputs before deferring work")
				require.Contains(t, continuation, "ex-sbom policy v1")
				require.Contains(t, continuation, "Repair version policy")
				require.Contains(t, continuation, "the same minor series for 0.x")
			} else {
				require.Contains(t, continuation, "請先查證缺項，再決定是否延後")
				require.Contains(t, continuation, "ex-sbom 排序規則 v1")
				require.Contains(t, continuation, "修補版本選擇")
				require.Contains(t, continuation, "0.x 限同一次要版本")
			}
			urgentRow := "2. " + tc.priority + " | " + urgentName
			require.Contains(t, continuation, urgentRow)
			elevatedRow := "3. " + tc.elevated + " | " + elevatedName
			scheduled := "Schedule assessment"
			if tc.language == "zh-Hant" {
				scheduled = "安排評估"
			}
			scheduledRow := "4. " + scheduled + " | " + nearBoundaryName
			reviewRow := "5. " + tc.review + " | " + reviewName
			_, afterElevated, found := strings.Cut(continuation, elevatedRow)
			require.True(t, found, elevatedRow)
			elevatedDetails, afterScheduled, found := strings.Cut(afterElevated, scheduledRow)
			require.True(t, found, scheduledRow)
			scheduledDetails, reviewDetails, found := strings.Cut(afterScheduled, reviewRow)
			require.True(t, found, reviewRow)
			require.Contains(t, elevatedDetails, tc.lowerBound+" 10%")
			require.Contains(t, scheduledDetails, "9.99% · EPSS")
			require.Contains(t, reviewDetails, tc.lowerBound+" 9.99%")

			properties, err := exec.Command(inspect, pdf).Output()
			require.NoError(t, err)
			require.Regexp(t, `(?m)^Tagged:\s+yes$`, string(properties))
			structure, err := exec.Command(inspect, "-struct-text", pdf).Output()
			require.NoError(t, err)
			for _, tag := range []string{" H1 ", " H2 ", " H3 ", "Link (inline)", "Table", "TH ", "/Scope /Column", "/Headers ["} {
				require.Contains(t, string(structure), tag)
			}
			require.Regexp(t, `(?m)^ +Link \(inline\)\n(?:[^\n]*\n){0,3} +/TextDecorationType /Underline\n +"\Q`+tc.continuationLink+`\E"$`, string(structure))
			destinations, err := exec.Command(inspect, "-dests", pdf).Output()
			require.NoError(t, err)
			require.Regexp(t, `(?m)^\s*2 \[.*\] "remediation-order"$`, string(destinations))

			if xmlExtractor, err := exec.LookPath("pdftohtml"); err == nil {
				verifyPriorityColors(t, xmlExtractor, pdf, map[string]string{
					"1. " + tc.priority + " |": "#801a24",
					urgentRow:                  "#801a24",
					elevatedRow:                "#754700",
				})
			}
		})
	}
}

func TestTaggedReportDownloadDistinguishesMissingUrgencyEvidence(t *testing.T) {
	extract, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext is required to verify the report homepage")
	}
	const knownCVE, otherCVE = "CVE-2099-1000", "CVE-2099-1001"
	checked := time.Date(2026, 11, 23, 1, 2, 3, 0, time.UTC)
	known := ssbom.Vuln{ID: knownCVE, CVEIDs: []string{knownCVE}, CVSSScore: "9.8", KEV: ssbom.KEVListed, KEVCVE: knownCVE}
	unknown := ssbom.Vuln{ID: otherCVE, CVEIDs: []string{otherCVE}, CVSSScore: "8.1"}
	unlisted := unknown
	unlisted.KEV = ssbom.KEVUnlisted

	for _, tc := range []struct {
		name, expectedCount, version string
		expectedEnglishCount         string
		source                       ssbom.ReportSource
		findings                     []ssbom.Vuln
	}{
		{"missing catalog", "待查證", "1.0.0", "Pending", ssbom.ReportSource{Status: ssbom.QueryCompleted}, []ssbom.Vuln{unknown}},
		{"partial query", "至少 1", "1.0.0", "At least 1", ssbom.ReportSource{Status: ssbom.QueryPartial, KEVCheckedAt: &checked}, []ssbom.Vuln{known}},
		{"one unchecked finding", "至少 1", "1.0.0", "At least 1", ssbom.ReportSource{Status: ssbom.QueryCompleted, KEVCheckedAt: &checked}, []ssbom.Vuln{known, unknown}},
		{"unconfirmed version", "待查證", "", "Pending", ssbom.ReportSource{Status: ssbom.QueryCompleted, KEVCheckedAt: &checked}, []ssbom.Vuln{known}},
		{"confirmed zero", "0", "1.0.0", "0", ssbom.ReportSource{Status: ssbom.QueryCompleted, KEVCheckedAt: &checked}, []ssbom.Vuln{unlisted}},
		{"no CVE to check", "0", "1.0.0", "0", ssbom.ReportSource{Status: ssbom.QueryCompleted}, []ssbom.Vuln{{ID: "TEST-LOCAL", CVSSScore: "8.1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bom := ssbom.FormattedSBOM{
				ReportSource: &tc.source,
				ComponentInfo: map[string]ssbom.Component{
					"example": {Name: "example", Version: tc.version, Vulns: tc.findings},
				},
			}
			cache := ssbom.NewInMemoryCache()
			cache.Set(1, "fixture", bom)
			handler := New(ssbom.NewService(reportRepository{}, cache))
			router := gin.New()
			router.GET("/projects/:id/sboms/:name/report", middleware.ProjectID(), handler.CreatePDF)
			for _, language := range []struct {
				code, count, urgent, kev, remaining, coverage string
			}{
				{"zh-Hant", tc.expectedCount, "需立即更新的元件", "列入 CISA KEV 的弱點", "仍需立即更新的元件", "涵蓋範圍待確認。需驗測修補版本並複掃後，才能確認處理結果。"},
				{"en", tc.expectedEnglishCount, "Components to update immediately", "CVEs listed in CISA KEV", "Components still requiring immediate updates", "Coverage is pending. Test a fix and rescan to confirm what it addresses."},
			} {
				t.Run(language.code, func(t *testing.T) {
					resp := httptest.NewRecorder()
					router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/projects/1/sboms/fixture/report?lang="+language.code, nil))
					require.Equal(t, http.StatusOK, resp.Code)

					cmd := exec.Command(extract, "-f", "1", "-l", "1", "-raw", "-", "-")
					cmd.Stdin = resp.Body
					raw, err := cmd.Output()
					require.NoError(t, err)
					home := strings.Join(strings.Fields(string(raw)), " ")
					for _, label := range []string{language.urgent, language.kev, language.remaining} {
						require.Contains(t, home, label+" "+language.count)
					}
					require.Contains(t, home, language.coverage)
				})
			}
		})
	}
}

func verifyPriorityColors(t *testing.T, extractor, pdf string, expected map[string]string) {
	t.Helper()
	raw, err := exec.Command(extractor, "-xml", "-stdout", "-i", pdf).Output()
	require.NoError(t, err)
	var document struct {
		Pages []struct {
			Fonts []struct {
				ID    string `xml:"id,attr"`
				Color string `xml:"color,attr"`
			} `xml:"fontspec"`
			Lines []struct {
				Font string `xml:"font,attr"`
				Text string `xml:",chardata"`
			} `xml:"text"`
		} `xml:"page"`
	}
	require.NoError(t, xml.Unmarshal(raw, &document))
	colors := make(map[string]string)
	headings := make(map[string]string)
	for _, page := range document.Pages {
		for _, font := range page.Fonts {
			colors[font.ID] = font.Color
		}
		for _, line := range page.Lines {
			for label := range expected {
				if strings.Contains(line.Text, label) {
					headings[label] = colors[line.Font]
				}
			}
		}
	}
	require.Equal(t, expected, headings)
}
