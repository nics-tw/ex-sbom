// SPDX-License-Identifier: MIT

//go:build unit && taggedpdf

package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"ex-sbom/client/first"
	"ex-sbom/internal/handler/middleware"
	ssbom "ex-sbom/internal/service/sbom"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func requireTaggedPDFTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil && os.Getenv("CI") != "true" {
		t.Skipf("%s is required to inspect tagged PDF output", name)
	}
	require.NoError(t, err)
	return path
}

func TestTaggedReportPreservesAccessibleFieldsAndLongVersions(t *testing.T) {
	extract := requireTaggedPDFTool(t, "pdftotext")
	inspect := requireTaggedPDFTool(t, "pdfinfo")
	fonts := requireTaggedPDFTool(t, "pdffonts")
	outline := requireTaggedPDFTool(t, "pdftohtml")
	const advisory = "CVE-2099-1000"
	const firstName = "first-component-with-a-long-package-name"
	version := "1.0.0-alpha.1+build.20260101." + strings.Repeat("0123456789abcdef", 6)
	longDetails := strings.Repeat("測試長字串", 5462)
	bom := ssbom.FormattedSBOM{
		ReportSource:     &ssbom.ReportSource{Status: ssbom.QueryCompleted, LEVArchiveStatus: ssbom.LEVArchiveDisabled},
		ComponentToLevel: map[string]int{"first": 0},
		ComponentInfo: map[string]ssbom.Component{
			"first": {Name: firstName, Version: version, Vulns: []ssbom.Vuln{{
				ID: advisory, Summary: "English advisory summary",
				Details: "English advisory details. \U0010FFFC\n\n" + longDetails,
			}}},
			"second": {Name: "second-component", Version: "2.3.4", Vulns: []ssbom.Vuln{{ID: advisory}}},
		},
	}
	cache := ssbom.NewInMemoryCache()
	cache.Set(1, "fixture", bom)
	handler := New(ssbom.NewService(reportRepository{}, cache))
	router := gin.New()
	router.GET("/projects/:id/sboms/:name/report", middleware.ProjectID(), handler.CreatePDF)
	t.Setenv("EX_SBOM_PDF_CACHE_DIR", filepath.Join(t.TempDir(), "cache"))

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/projects/1/sboms/fixture/report?lang=zh-Hant", nil))
	require.Equal(t, http.StatusOK, response.Code)
	pdf := filepath.Join(t.ArtifactDir(), "report-long-version.pdf")
	require.NoError(t, os.WriteFile(pdf, response.Body.Bytes(), 0600))

	raw, err := exec.Command(extract, "-enc", "UTF-8", "-eol", "unix", "-raw", pdf, "-").Output()
	require.NoError(t, err)
	text := strings.ReplaceAll(string(raw), "\u200b", "")
	_, inventory, ok := strings.Cut(text, "元件清單")
	require.Truef(t, ok, "missing inventory heading in %s output (%d bytes, valid UTF-8: %t), prefix %q",
		extract, len(raw), utf8.Valid(raw), raw[:min(len(raw), 512)])
	inventory, _, ok = strings.Cut(inventory, "弱點明細")
	require.True(t, ok)
	require.Contains(t, strings.Join(strings.Fields(inventory), ""), version)
	bounds, err := exec.Command(extract, "-enc", "UTF-8", "-bbox-layout", pdf, "-").Output()
	require.NoError(t, err)
	requireVersionColumnBounds(t, bounds, version)
	require.Contains(t, strings.Join(strings.Fields(text), " "), "摘要 English advisory summary")
	require.Contains(t, text, "版本 未記錄")
	require.Contains(t, text, "文字顯示說明")
	require.Contains(t, text, "English advisory details. \U0010FFFC")
	var extractedDetails strings.Builder
	for _, r := range text {
		if strings.ContainsRune("測試長字串", r) {
			extractedDetails.WriteRune(r)
		}
	}
	require.True(t, strings.Contains(extractedDetails.String(), longDetails), "the long advisory text must remain intact across pages (%d of %d bytes extracted)", extractedDetails.Len(), len(longDetails))
	require.Equal(t, 1, strings.Count(text, "LEV 掃描時未啟用"))
	require.NotContains(t, text, "LEV 未取得或未驗證")
	require.NotContains(t, text, "弱點識別碼")

	structure, err := exec.Command(inspect, "-enc", "UTF-8", "-struct-text", pdf).Output()
	require.NoError(t, err)
	structureText := strings.ReplaceAll(string(structure), "\r\n", "\n")
	require.Regexp(t, `(?m)^  P \(block\)\n    "專案"\n    " 測試專案"\n  P \(block\)\n    "版本"\n    " fixture"`, structureText)
	_, firstAction, found := strings.Cut(structureText, `"優先交辦項目"`)
	require.True(t, found, "missing priority action on the report homepage")
	firstAction, _, found = strings.Cut(firstAction, `"若本輪只完成第 1 項"`)
	require.True(t, found, "missing the coverage section after the first action")
	require.Regexp(t, `(?m)^ +P \(block\)\n +"依據"\n +" `+advisory, firstAction,
		"the first action's evidence label and value must share a paragraph")
	require.Contains(t, string(structure), advisory+" · second-component 2.3.4")
	bookmarks, err := exec.Command(outline, "-enc", "UTF-8", "-q", "-xml", "-i", "-stdout", pdf).Output()
	require.NoError(t, err)
	require.True(t, strings.Contains(string(bookmarks), advisory+" · "+firstName+" "+version+"</item>"), "the long bookmark title must preserve the source text")
	require.True(t, strings.Contains(string(bookmarks), advisory+" · second-component 2.3.4</item>"), "bookmarks must identify each affected component")
	require.Regexp(t, `/Lang\s*\(zh-TW\)`, response.Body.String())
	require.GreaterOrEqual(t, len(regexp.MustCompile(`/Lang\s*\(en\)`).FindAll(response.Body.Bytes(), -1)), 2)
	fontList, err := exec.Command(fonts, pdf).Output()
	require.NoError(t, err)
	require.Contains(t, string(fontList), "NotoSansCJKtc-Bold")
}

func requireVersionColumnBounds(t *testing.T, bounds []byte, version string) {
	t.Helper()
	var layout struct {
		Pages []struct {
			Blocks []struct {
				Words []struct {
					XMin float64 `xml:"xMin,attr"`
					XMax float64 `xml:"xMax,attr"`
					Text string  `xml:",chardata"`
				} `xml:"line>word"`
			} `xml:"flow>block"`
		} `xml:"body>doc>page"`
	}
	require.NoError(t, xml.Unmarshal(bounds, &layout))
	for _, page := range layout.Pages {
		var inventory bool
		var scopeColumn, versionEnd float64
		for _, block := range page.Blocks {
			var text strings.Builder
			var rightEdge float64
			for _, word := range block.Words {
				text.WriteString(strings.ReplaceAll(word.Text, "\u200b", ""))
				rightEdge = max(rightEdge, word.XMax)
			}
			switch text.String() {
			case "元件清單":
				inventory = true
			case "直接":
				if inventory {
					scopeColumn = block.Words[0].XMin
				}
			case version:
				if inventory {
					versionEnd = rightEdge
				}
			}
		}
		if inventory {
			require.Positive(t, scopeColumn, "missing the scope in the long version's row")
			require.Positive(t, versionEnd, "missing the long version's bounds")
			require.Less(t, versionEnd, scopeColumn, "long version crosses into the adjacent scope column")
			return
		}
	}
	t.Fatal("missing the inventory page")
}

func TestTaggedReportDownloadReturnsServiceUnavailableWhenRenderingTimesOut(t *testing.T) {
	t.Setenv("EX_SBOM_PDF_TIMEOUT", "1ns")
	cache := ssbom.NewInMemoryCache()
	cache.Set(1, "fixture", ssbom.FormattedSBOM{})
	handler := New(ssbom.NewService(reportRepository{}, cache))
	router := gin.New()
	router.GET("/projects/:id/sboms/:name/report", middleware.ProjectID(), handler.CreatePDF)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/projects/1/sboms/fixture/report", nil))
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.Contains(t, response.Body.String(), "PDF rendering timed out")
}

func TestTaggedReportDownloadIdentifiesUnusableCache(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "not-a-directory")
	require.NoError(t, os.WriteFile(blocked, nil, 0600))
	t.Setenv("EX_SBOM_PDF_CACHE_DIR", blocked)
	cache := ssbom.NewInMemoryCache()
	cache.Set(1, "fixture", ssbom.FormattedSBOM{})
	router := gin.New()
	router.GET("/projects/:id/sboms/:name/report", middleware.ProjectID(), New(ssbom.NewService(reportRepository{}, cache)).CreatePDF)
	download := func() *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/projects/1/sboms/fixture/report", nil))
		return response
	}

	response := download()
	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.JSONEq(t, `{"error":"failed to create PDF","code":"pdf_cache_unavailable"}`, response.Body.String())
	t.Setenv("EX_SBOM_PDF_CACHE_DIR", filepath.Join(dir, "cache"))
	response = download()
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "application/pdf", response.Header().Get("Content-Type"))
}

func TestTaggedReportDownloadPreservesPrioritiesAndEvidence(t *testing.T) {
	extract := requireTaggedPDFTool(t, "pdftotext")
	inspect := requireTaggedPDFTool(t, "pdfinfo")

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
				Vulns: []ssbom.Vuln{{ID: "TEST-REVIEW", CVSSScore: "6.9", EPSS: "0.099999", KEV: ssbom.KEVUnlisted}},
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
			"Prioritize fix assessment", "Assess next", "At least", "Components with unclassified findings",
			"CVEs expected to be addressed across all known affected components", "View remediation order",
		},
		{
			"zh-Hant", "立即更新", "建議驗測版本", "預計涵蓋的 KEV 弱點",
			"此版本未確認涵蓋的 KEV 弱點", "仍需立即更新的元件",
			"優先評估修補", "待評估", "至少", "含未分級弱點的元件",
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

			raw, err := exec.Command(extract, "-enc", "UTF-8", "-eol", "unix", "-raw", pdf, "-").Output()
			require.NoError(t, err)
			home, later, ok := strings.Cut(strings.ReplaceAll(string(raw), "\u200b", ""), "\f")
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
				require.Contains(t, continuation, "ex-sbom policy v2")
				require.Contains(t, continuation, "Repair version policy")
				require.Contains(t, continuation, "the same minor series for 0.x")
			} else {
				require.Contains(t, continuation, "請先查證缺項，再決定是否延後")
				require.Contains(t, continuation, "ex-sbom 排序規則 v2")
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
			require.Regexp(t, `(?m)^Tagged:\s+yes\r?$`, string(properties))
			structure, err := exec.Command(inspect, "-enc", "UTF-8", "-struct-text", pdf).Output()
			require.NoError(t, err)
			structureText := strings.ReplaceAll(string(structure), "\r\n", "\n")
			for _, tag := range []string{" H1 ", " H2 ", " H3 ", "Link (inline)", "Table", "TH ", "/Scope /Column", "/Headers ["} {
				require.Contains(t, structureText, tag)
			}
			require.Regexp(t, `(?m)^ +Link \(inline\)\n(?:[^\n]*\n){0,3} +/TextDecorationType /Underline\n +"\Q`+tc.continuationLink+`\E"$`, structureText)
			destinations, err := exec.Command(inspect, "-dests", pdf).Output()
			require.NoError(t, err)
			require.Regexp(t, `(?m)^\s*2 \[.*\] "remediation-order"\r?$`, string(destinations))

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
	extract := requireTaggedPDFTool(t, "pdftotext")
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

					cmd := exec.Command(extract, "-enc", "UTF-8", "-eol", "unix", "-f", "1", "-l", "1", "-raw", "-", "-")
					cmd.Stdin = resp.Body
					raw, err := cmd.Output()
					require.NoError(t, err)
					home := strings.Join(strings.Fields(string(raw)), " ")
					for _, label := range []string{language.urgent, language.remaining} {
						require.Contains(t, home, label+" "+language.count)
					}
					kevCount := language.count
					if tc.version == "" {
						kevCount = "1"
					}
					require.Contains(t, home, language.kev+" "+kevCount)
					require.Contains(t, home, language.coverage)
				})
			}
		})
	}
}

func verifyPriorityColors(t *testing.T, extractor, pdf string, expected map[string]string) {
	t.Helper()
	raw, err := exec.Command(extractor, "-enc", "UTF-8", "-xml", "-stdout", "-i", pdf).Output()
	require.NoError(t, err)
	var document struct {
		Pages []struct {
			Fonts []struct {
				ID    string `xml:"id,attr"`
				Color string `xml:"color,attr"`
			} `xml:"fontspec"`
			Lines []struct {
				Font string `xml:"font,attr"`
				Text string `xml:",innerxml"`
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
			var content strings.Builder
			decoder := xml.NewDecoder(strings.NewReader(line.Text))
			for {
				token, err := decoder.Token()
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
				if chars, ok := token.(xml.CharData); ok {
					content.Write(chars)
				}
			}
			rendered := strings.ReplaceAll(content.String(), "\u200b", "")
			for label := range expected {
				if strings.Contains(rendered, label) {
					headings[label] = colors[line.Font]
				}
			}
		}
	}
	require.Equal(t, expected, headings)
}
