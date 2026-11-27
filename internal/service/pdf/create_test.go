// SPDX-License-Identifier: MIT

//go:build unit

package pdf

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"ex-sbom/internal/domain"
	ssbom "ex-sbom/internal/service/sbom"

	"github.com/stretchr/testify/require"
)

func TestQueryStatusWording(t *testing.T) {
	for _, tc := range []struct {
		status   ssbom.QueryStatus
		findings int
		zh, en   string
	}{
		{ssbom.QueryCompleted, 0, "查詢完成，未發現已知弱點", "Query completed. No known vulnerabilities found."},
		{ssbom.QueryCompleted, 1, "查詢完成，已列出弱點紀錄", "Query completed. Findings are listed below."},
		{ssbom.QueryPartial, 0, "查詢部分完成，涵蓋範圍或回傳的弱點紀錄尚未完整確認", "Query partially completed. Coverage or returned findings could not be fully confirmed."},
		{ssbom.QueryNotRun, 0, "未執行弱點查詢", "No vulnerability query was performed."},
		{ssbom.QueryFailed, 0, "弱點查詢失敗", "Vulnerability query failed."},
		{"", 0, "查詢狀態未記錄", "Query status was not recorded."},
	} {
		require.Equal(t, tc.zh, (&document{language: TraditionalChinese}).queryStatus(tc.status, tc.findings))
		require.Equal(t, tc.en, (&document{language: English}).queryStatus(tc.status, tc.findings))
	}
}

func TestRemediationHomepageWithoutFindings(t *testing.T) {
	extract, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext is required to verify the PDF homepage")
	}
	for _, lang := range []string{English, TraditionalChinese} {
		for _, status := range []ssbom.QueryStatus{
			ssbom.QueryCompleted, ssbom.QueryPartial, ssbom.QueryNotRun, ssbom.QueryFailed, "",
		} {
			t.Run(lang+"/"+string(status), func(t *testing.T) {
				var output bytes.Buffer
				require.NoError(t, generateUntagged(&output, Report{
					Language: lang,
					SBOM:     ssbom.FormattedSBOM{ReportSource: &ssbom.ReportSource{Status: status}},
				}))
				cmd := exec.Command(extract, "-enc", "UTF-8", "-eol", "unix", "-f", "1", "-l", "1", "-layout", "-", "-")
				cmd.Stdin = &output
				page, err := cmd.Output()
				require.NoError(t, err)
				text := string(page)
				doc := &document{language: lang}
				require.Contains(t, text, doc.label("Remediation summary", "修補摘要"))
				require.Contains(t, text, doc.queryStatus(status, 0))
				caution := doc.label("No remediation order", "目前無法判定修補順序")
				empty := doc.label("No remediation items for this query.", "本次無修補項目。")
				if status == ssbom.QueryCompleted {
					require.Contains(t, text, empty)
					require.NotContains(t, text, caution)
				} else {
					require.NotContains(t, text, empty)
					require.Contains(t, text, caution)
					require.NotContains(t, text, doc.queryStatus(ssbom.QueryCompleted, 0))
				}
			})
		}
	}
}

func pdfConfirmedVersion(name, version string) *ssbom.InstalledVersionEvidence {
	return &ssbom.InstalledVersionEvidence{Ecosystem: "npm", Package: name, Version: version, Confirmed: true}
}

func TestRemediationHomepageLinksToAdditionalUrgentFindings(t *testing.T) {
	extract, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext is required to verify the PDF homepage")
	}
	checked := time.Date(2026, 11, 23, 1, 2, 3, 0, time.UTC)
	bom := ssbom.FormattedSBOM{
		ReportSource:  &ssbom.ReportSource{Status: ssbom.QueryCompleted, KEVCheckedAt: &checked},
		ComponentInfo: map[string]ssbom.Component{},
	}
	for _, key := range []string{"a", "b", "c", "d"} {
		bom.ComponentInfo[key] = ssbom.Component{
			Name: key + "-" + strings.Repeat("long-component-name-", 20), Version: "1.0.0",
			InstalledVersion: pdfConfirmedVersion(key, "1.0.0"),
			Vulns: []ssbom.Vuln{{ID: "CVE-2025-0001", CVEIDs: []string{"CVE-2025-0001"},
				KEV: ssbom.KEVListed, KEVCVE: "CVE-2025-0001"}},
		}
	}
	for _, lang := range []string{English, TraditionalChinese} {
		t.Run(lang, func(t *testing.T) {
			var output bytes.Buffer
			require.NoError(t, generateUntagged(&output, Report{Language: lang, SBOM: bom}))
			require.Contains(t, output.String(), "/Subtype /Link")
			require.Contains(t, output.String(), "/Dest [")
			cmd := exec.Command(extract, "-enc", "UTF-8", "-eol", "unix", "-layout", "-", "-")
			cmd.Stdin = &output
			raw, err := cmd.Output()
			require.NoError(t, err)
			pages := strings.Split(string(raw), "\f")
			doc := &document{language: lang}
			require.Contains(t, pages[0], doc.label("Additional components to update immediately | 3", "另有需立即更新的元件 | 3"))
			require.Contains(t, pages[0], doc.label("View remediation order", "查看修補順序表"))
			require.Contains(t, pages[0], doc.label("1. Update immediately |", "1. 立即更新 |"))
			require.NotContains(t, pages[0], doc.label("2. Update immediately |", "2. 立即更新 |"))
			continuation := strings.Join(pages[1:], "\n")
			require.Contains(t, continuation, doc.label("2. Update immediately |", "2. 立即更新 |"))
			require.Contains(t, continuation, doc.label("4. Update immediately |", "4. 立即更新 |"))
			require.Contains(t, continuation, "d-long-component-name-")
		})
	}
}

func TestPDFRemediationOrderListsEveryScoredComponent(t *testing.T) {
	extract, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext required to verify PDF remediation order")
	}
	bom := ssbom.FormattedSBOM{
		ReportSource: &ssbom.ReportSource{Status: ssbom.QueryCompleted},
		ComponentInfo: map[string]ssbom.Component{
			"first": {Name: "rank-first", Version: "2.0", Vulns: []ssbom.Vuln{
				{ID: "TEST-1", CVSSScore: "8.8", EPSS: "0.2"},
				{ID: "TEST-2", CVSSScore: "10", EPSS: "0.02"},
			}},
			"second": {Name: "rank-second", Version: "2.0", Vulns: []ssbom.Vuln{
				{ID: "TEST-3", CVSSScore: "9.8", EPSS: "0.15"},
			}},
			"missing": {Name: "rank-missing", Version: "2.0", Vulns: []ssbom.Vuln{
				{ID: "TEST-4", CVSSScore: "7.5"},
			}},
			"zero": {Name: "rank-zero", Version: "2.0", Vulns: []ssbom.Vuln{
				{ID: "TEST-5", CVSSScore: "0"},
			}},
			"clean": {Name: "rank-clean", Version: "2.0"},
		},
	}
	for _, lang := range []string{English, TraditionalChinese} {
		t.Run(lang, func(t *testing.T) {
			doc := &document{language: lang}
			var output bytes.Buffer
			require.NoError(t, Generate(&output, Report{Language: lang, SBOM: bom}))
			cmd := exec.Command(extract, "-enc", "UTF-8", "-eol", "unix", "-layout", "-", "-")
			cmd.Stdin = &output
			raw, err := cmd.Output()
			require.NoError(t, err)
			first, remaining, found := strings.Cut(string(raw), "\f")
			require.True(t, found)
			require.Contains(t, first, doc.label("View remediation order", "查看修補順序表"))
			table, _, found := strings.Cut(remaining, doc.label("Remediation priorities (continued)", "修補處理順序（續）"))
			require.True(t, found)
			table = strings.Join(strings.Fields(table), " ")
			require.Contains(t, table, doc.label("Max CVSS", "最高 CVSS"))
			require.NotContains(t, table, "rank-clean")
			order := []string{"1 rank-first 2.0 10", "2 rank-second 2.0 9.8", "3 rank-missing 2.0 7.5", "4 rank-zero 2.0 0"}
			last := -1
			for _, row := range order {
				position := strings.Index(table, row)
				require.Greater(t, position, last, table)
				last = position
			}
		})
	}
}

func TestRemediationHomepageKEVEvidence(t *testing.T) {
	extract, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext is required to verify the PDF homepage")
	}
	checked := time.Date(2026, 11, 23, 1, 2, 3, 0, time.UTC)
	legacy := ssbom.Vuln{ID: "CVE-2025-0001"}
	listed := ssbom.Vuln{ID: "CVE-2025-0002", CVEIDs: []string{"CVE-2025-0002"},
		KEV: ssbom.KEVListed, KEVCVE: "CVE-2025-0002"}
	unlisted := ssbom.Vuln{ID: "CVE-2025-0003", CVEIDs: []string{"CVE-2025-0003"}, KEV: ssbom.KEVUnlisted}
	for _, tc := range []struct {
		name      string
		findings  []ssbom.Vuln
		checked   *time.Time
		count     string
		confirmed bool
		kevCount  string
	}{
		{"legacy CVE", []ssbom.Vuln{legacy}, nil, "Pending", false, "Pending"},
		{"legacy CVE alongside checked CVE", []ssbom.Vuln{legacy, listed}, &checked, "At least 1", true, "At least 1"},
		{"KEV with legacy display version", []ssbom.Vuln{listed}, &checked, "Pending", false, "1"},
		{"checked CVE and finding without CVE", []ssbom.Vuln{unlisted, {ID: "GHSA-test"}}, &checked, "0", false, "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bom := ssbom.FormattedSBOM{
				ReportSource: &ssbom.ReportSource{Status: ssbom.QueryCompleted, KEVCheckedAt: tc.checked},
				ComponentInfo: map[string]ssbom.Component{
					"example": {Name: "example", Version: "1.0.0", Vulns: tc.findings},
				},
			}
			if tc.confirmed {
				component := bom.ComponentInfo["example"]
				component.InstalledVersion = pdfConfirmedVersion("example", component.Version)
				bom.ComponentInfo["example"] = component
			}
			var output bytes.Buffer
			require.NoError(t, Generate(&output, Report{Language: English, SBOM: bom}))
			cmd := exec.Command(extract, "-enc", "UTF-8", "-eol", "unix", "-f", "1", "-l", "1", "-raw", "-", "-")
			cmd.Stdin = &output
			page, err := cmd.Output()
			require.NoError(t, err)
			text := strings.Join(strings.Fields(string(page)), " ")
			require.Contains(t, text, "Components to update immediately "+tc.count)
			require.Contains(t, text, "CVEs listed in CISA KEV "+tc.kevCount)
			if tc.name == "KEV with legacy display version" {
				require.Contains(t, text, "Upgrade to test Pending")
				require.Contains(t, text, "Confirm the installed version")
				require.Contains(t, text, "Coverage is pending")
			}
		})
	}
}

func TestGenerateSearchableMultilingualPDF(t *testing.T) {
	generatedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	name := "元件名稱/" + strings.Repeat("long-package-", 35)
	bom := ssbom.FormattedSBOM{
		ComponentToLevel: map[string]int{"urgent": 1},
		ComponentInfo: map[string]ssbom.Component{
			name: {Name: name, Version: "1.0",
				Vulns: []ssbom.Vuln{{ID: "TEST-EX-SBOM-0001", CVSSScore: "8.4", EPSS: "0.02", LEV: "0.937221", SuggestFixVersion: "9.9.9",
					Summary: "弱點摘要", Details: strings.Repeat("跨頁內容 Mixed-language text. ", 400) + "末頁標記"}}},
			"urgent": {Name: "urgent-package", Version: "1.0.0", InstalledVersion: pdfConfirmedVersion("urgent-package", "1.0.0"), Vulns: []ssbom.Vuln{
				{ID: "CVE-2024-0001", CVSSScore: "8.0", KEV: ssbom.KEVListed, KEVCVE: "CVE-2024-0001", CVEIDs: []string{"CVE-2024-0001"},
					RepairEvidence: &ssbom.RepairEvidence{AdvisoryID: "CVE-2024-0001", Ecosystem: "npm", Package: "urgent-package", Installed: "1.0.0",
						Ranges: []ssbom.RepairInterval{{Start: "0", Fixed: "1.2.3"}}}},
				{ID: "CVE-2024-0002", CVSSScore: "6.5", KEV: ssbom.KEVListed, KEVCVE: "CVE-2024-0002", CVEIDs: []string{"CVE-2024-0002"}},
			}},
		},
		ReportSource: &ssbom.ReportSource{
			FileName: "來源測試.json", FileSHA256: strings.Repeat("e", 64),
			Specification: "CycloneDX 1.7", Status: ssbom.QueryPartial, QueriedAt: &generatedAt,
		},
	}
	for _, tc := range []struct{ language, title, count string }{
		{English, "Software Bill of Materials (SBOM) Analysis Report", "Component-vulnerability findings"},
		{TraditionalChinese, "軟體物料清單（SBOM）分析報告", "元件弱點紀錄數"},
	} {
		t.Run(tc.language, func(t *testing.T) {
			var output bytes.Buffer
			err := generateUntagged(&output, Report{Project: domain.ProjectInfo{ID: 12, Name: "測試專案"},
				Version: "候選版", GeneratedAt: generatedAt, Language: tc.language, SBOM: bom})
			require.NoError(t, err)
			require.True(t, bytes.HasPrefix(output.Bytes(), []byte("%PDF-")))
			require.Contains(t, output.String(), "/ToUnicode")
			require.Contains(t, output.String(), "/FontFile2")
			if command, err := exec.LookPath("pdftotext"); err == nil {
				cmd := exec.Command(command, "-enc", "UTF-8", "-eol", "unix", "-layout", "-", "-")
				cmd.Stdin = bytes.NewReader(output.Bytes())
				result, err := cmd.Output()
				require.NoError(t, err)
				text := string(result)
				require.GreaterOrEqual(t, strings.Count(text, "\f"), 3)
				require.Contains(t, text, tc.title)
				firstPage := strings.Split(text, "\f")[0]
				require.NotContains(t, firstPage, "100% · KEV")
				doc := &document{language: tc.language}
				previous := -1
				for _, label := range []string{
					doc.label("Remediation summary", "修補摘要"),
					doc.label("Priority action", "優先交辦項目"),
					doc.label("Known exploitation (CISA KEV)", "已知遭利用（CISA KEV）"),
					doc.label("If only action 1 is completed", "若本輪只完成第 1 項"),
				} {
					position := strings.Index(firstPage, label)
					require.Greater(t, position, previous, label)
					previous = position
				}
				require.Contains(t, text[len(firstPage):], doc.label("Ranking policy", "排序規則"))
				if tc.language == TraditionalChinese {
					require.Contains(t, firstPage, "部分資料仍待確認")
					require.Contains(t, text, "共同修補版本 | 尚未驗證")
					require.Contains(t, text, "此弱點的公告修補候選 | 9.9.9")
				} else {
					require.Contains(t, firstPage, "Evidence incomplete")
					require.Contains(t, text, "Common fix version | Unverified.")
					require.Contains(t, text, "Advisory candidates for this finding | 9.9.9")
				}
				require.Contains(t, text, tc.count+" | 3")
				require.NotContains(t, text, "0.937221")
				if tc.language == TraditionalChinese {
					require.Contains(t, strings.Split(text, "\f")[0], "1. 立即更新 | urgent-package 1.0.0")
					require.Contains(t, strings.Split(text, "\f")[0], "確認上游相依元件")
					require.Regexp(t, `建議驗測版本[ \t]+1[.]2[.]3`, firstPage)
					require.Contains(t, strings.Split(text, "\f")[0], "累計預計處理的元件弱點紀錄 | 1")
					require.Regexp(t, `建議驗測版本[ \t]+1[.]2[.]3\s+預計涵蓋的 KEV 弱點[ \t]+CVE-2024-0001\s+此版本未確認涵蓋的 KEV 弱點[ \t]+CVE-2024-0002`, firstPage)
					require.Contains(t, text, "LEV | 未取得或未驗證")
					require.Contains(t, text, "至少 2%（資料未齊）")
					require.Contains(t, text, "建議升級的涵蓋情形 | 1.2.3 · 預計可處理此弱點")
					require.Contains(t, text, "建議升級的涵蓋情形 | 1.2.3 · 尚未確認涵蓋")
				} else {
					require.Contains(t, strings.Split(text, "\f")[0], "1. Update immediately | urgent-package 1.0.0")
					require.Regexp(t, `Identify the parent\s+dependency`, firstPage)
					require.Regexp(t, `Upgrade to test[ \t]+1[.]2[.]3`, firstPage)
					require.Contains(t, strings.Split(text, "\f")[0], "Cumulative findings expected to be addressed | 1")
					require.Regexp(t, `Upgrade to test[ \t]+1[.]2[.]3\s+KEV findings expected to be[ \t]+CVE-2024-0001\s+addressed\s+KEV findings without confirmed[ \t]+CVE-2024-0002\s+coverage in this version`, firstPage)
					require.Contains(t, text, "LEV | Unavailable or unverified")
					require.Contains(t, text, "At least 2% (incomplete data)")
					require.Contains(t, text, "Coverage of proposed upgrade | 1.2.3 · Expected to address this finding")
					require.Contains(t, text, "Coverage of proposed upgrade | 1.2.3 · Coverage not established")
				}
				for _, value := range []string{"測試專案", "候選版", "來源測試.json", strings.Repeat("e", 64), "TEST-EX-SBOM-0001", "末頁標記"} {
					require.Contains(t, text, value)
				}
				require.NotContains(t, text, "未發現已知弱點")
				require.NotContains(t, text, "No known vulnerabilities found")
			}
		})
	}
}

func TestFormatReportFileName(t *testing.T) {
	created := time.Date(2026, 11, 22, 10, 23, 42, 0, time.UTC)
	require.Equal(t, "正式版_1_2_report_20261122_102342.pdf", FileName("正式版/1\n2", created))
	require.Equal(t, "sbom_report_20261122_102342.pdf", FileName("   ", created))
}

func TestGenerateRepeatsInventoryHeadingsAndPreservesRowsAcrossPages(t *testing.T) {
	tool, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext is required to verify paginated inventory content")
	}
	const segmentCount = 360
	segments := make([]string, segmentCount)
	for i := range segments {
		segments[i] = fmt.Sprintf("row-segment-%03d", i)
	}
	segmentPattern := regexp.MustCompile(`row-segment-\d{3}`)
	for _, tc := range []struct {
		language, section string
		columns           []string
	}{
		{English, "Component inventory", []string{"Component", "Version", "Scope", "Findings"}},
		{TraditionalChinese, "元件清單", []string{"元件", "版本", "類型", "弱點數"}},
	} {
		t.Run(tc.language, func(t *testing.T) {
			columnPatterns := make([]string, len(tc.columns))
			for i, column := range tc.columns {
				columnPatterns[i] = regexp.QuoteMeta(column)
			}
			headingRow := regexp.MustCompile(`(?m)^[ \t]*` + strings.Join(columnPatterns, `[ \t]+`) + `[ \t]*$`)
			var output bytes.Buffer
			bom := ssbom.FormattedSBOM{ComponentInfo: map[string]ssbom.Component{
				"a": {Name: "before-inventory-row", Version: "before-version"},
				"b": {Name: strings.Join(segments, " "), Version: "spanning-version"},
				"c": {Name: "after-inventory-row", Version: "after-version"},
			}}
			require.NoError(t, generateUntagged(&output, Report{Language: tc.language, SBOM: bom}))
			command := exec.Command(tool, "-enc", "UTF-8", "-eol", "unix", "-layout", "-", "-")
			command.Stdin = bytes.NewReader(output.Bytes())
			result, err := command.CombinedOutput()
			require.NoError(t, err, string(result))
			text := string(result)
			require.Equal(t, segments, segmentPattern.FindAllString(text, -1))
			spanningPages := 0
			for _, page := range strings.Split(text, "\f") {
				firstSegment := segmentPattern.FindStringIndex(page)
				if firstSegment == nil {
					continue
				}
				spanningPages++
				_, afterSection, found := strings.Cut(page[:firstSegment[0]], tc.section)
				require.True(t, found, "missing inventory section heading on page %d", spanningPages)
				require.Regexp(t, headingRow, afterSection, "missing inventory column headings on page %d", spanningPages)
			}
			require.GreaterOrEqual(t, spanningPages, 2)
			for _, marker := range []string{"before-inventory-row", "before-version", "spanning-version", "after-inventory-row", "after-version"} {
				require.Equal(t, 1, strings.Count(text, marker), marker)
			}
			require.Less(t, strings.Index(text, "before-inventory-row"), strings.Index(text, segments[0]))
			require.Greater(t, strings.Index(text, "after-inventory-row"), strings.Index(text, segments[segmentCount-1]))
		})
	}
}

func TestGeneratePreservesOriginalTextForUnavailableGlyphs(t *testing.T) {
	for _, language := range []string{English, TraditionalChinese} {
		t.Run(language, func(t *testing.T) {
			var output bytes.Buffer
			report := Report{
				Project:  domain.ProjectInfo{Name: "𠮷祥專案"},
				Version:  "release-🧪-1",
				Language: language,
				SBOM:     ssbom.FormattedSBOM{Components: []string{"測試𠮷元件", "control\u202Etest"}},
			}
			require.NoError(t, generateUntagged(&output, report))
			require.True(t, bytes.HasPrefix(output.Bytes(), []byte("%PDF-1.4")))
			if tool, err := exec.LookPath("pdftotext"); err == nil {
				command := exec.Command(tool, "-enc", "UTF-8", "-eol", "unix", "-layout", "-", "-")
				command.Stdin = bytes.NewReader(output.Bytes())
				result, err := command.CombinedOutput()
				require.NoError(t, err, string(result))
				for _, original := range []string{"𠮷祥專案", "release-🧪-1", "測試𠮷元件", "control[U+202E]test"} {
					require.Contains(t, string(result), original)
				}
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestGeneratePropagatesWriteFailure(t *testing.T) {
	require.ErrorContains(t, generateUntagged(failingWriter{}, Report{GeneratedAt: time.Now()}), "write failed")
}

func TestRemediationHomepageKeepsCheckpointWithManyKEVFindings(t *testing.T) {
	extract, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext is required to verify the PDF homepage")
	}

	findings := make([]ssbom.Vuln, 96)
	for i := range findings {
		id := fmt.Sprintf("CVE-2099-%04d", 1000+i)
		findings[i] = ssbom.Vuln{ID: id, CVEIDs: []string{id}, KEV: ssbom.KEVListed, KEVCVE: id}
	}
	for _, lang := range []string{TraditionalChinese, English} {
		t.Run(lang, func(t *testing.T) {
			var output bytes.Buffer
			bom := ssbom.FormattedSBOM{
				ComponentInfo: map[string]ssbom.Component{
					"one": {Name: "first-" + strings.Repeat("long-component-name-", 36), Version: "1.0.0", InstalledVersion: pdfConfirmedVersion("first", "1.0.0"), Vulns: findings},
				},
			}
			require.NoError(t, generateUntagged(&output, Report{Language: lang, SBOM: bom}))

			command := exec.Command(extract, "-enc", "UTF-8", "-eol", "unix", "-layout", "-", "-")
			command.Stdin = &output
			extracted, err := command.Output()
			require.NoError(t, err)
			homepage, details, _ := strings.Cut(string(extracted), "")
			doc := &document{language: lang}
			require.Contains(t, homepage, doc.label("If only action 1 is completed", "若本輪只完成第 1 項"))
			require.Contains(t, homepage, doc.label("Next action", "下一步"))
			require.Contains(t, strings.Join(strings.Fields(homepage), " "),
				doc.label("92 more in vulnerability details", "另有 92 筆見弱點明細"))
			require.NotContains(t, homepage, "CVE-2099-1095")
			for _, finding := range findings {
				require.Contains(t, details, finding.ID)
			}
		})
	}
}
