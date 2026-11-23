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

func TestGenerateSearchableMultilingualPDF(t *testing.T) {
	generatedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	name := "元件名稱/" + strings.Repeat("long-package-", 35)
	bom := ssbom.FormattedSBOM{
		ComponentInfo: map[string]ssbom.Component{
			name: {Name: name, Version: "1.0",
				Vulns: []ssbom.Vuln{{ID: "TEST-EX-SBOM-0001", CVSSScore: "8.4", EPSS: "0.02", LEV: "0.937221",
					Summary: "弱點摘要", Details: strings.Repeat("跨頁內容 Mixed-language text. ", 400) + "末頁標記"}}},
			"urgent": {Name: "urgent-package", Version: "1.0", Vulns: []ssbom.Vuln{
				{ID: "CVE-2024-0001", CVSSScore: "8.0", KEV: ssbom.KEVListed, KEVCVE: "CVE-2024-0001", CVEIDs: []string{"CVE-2024-0001"},
					RepairEvidence: &ssbom.RepairEvidence{AdvisoryID: "CVE-2024-0001", Ecosystem: "npm", Package: "urgent-package", Installed: "1.0",
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
			err := Generate(&output, Report{Project: domain.ProjectInfo{ID: 12, Name: "測試專案"},
				Version: "候選版", GeneratedAt: generatedAt, Language: tc.language, SBOM: bom})
			require.NoError(t, err)
			require.True(t, bytes.HasPrefix(output.Bytes(), []byte("%PDF-")))
			require.Contains(t, output.String(), "/ToUnicode")
			require.Contains(t, output.String(), "/FontFile2")
			if command, err := exec.LookPath("pdftotext"); err == nil {
				cmd := exec.Command(command, "-layout", "-", "-")
				cmd.Stdin = bytes.NewReader(output.Bytes())
				result, err := cmd.Output()
				require.NoError(t, err)
				text := string(result)
				require.GreaterOrEqual(t, strings.Count(text, "\f"), 3)
				require.Contains(t, text, tc.title)
				require.Contains(t, text, tc.count+" | 3")
				require.NotContains(t, text, "0.937221")
				if tc.language == TraditionalChinese {
					require.Contains(t, strings.Split(text, "\f")[0], "1. 立即查證 | urgent-package 1.0")
					require.Contains(t, strings.Split(text, "\f")[0], "建議驗測版本 | 1.2.3")
					require.Contains(t, strings.Split(text, "\f")[0], "累計預計處理的元件弱點紀錄 | 1")
					require.Contains(t, strings.Split(text, "\f")[0], "仍待處理的 KEV 弱點 | CVE-2024-0002")
					require.Contains(t, text, "LEV | 未取得或未驗證")
					require.Contains(t, text, "至少 2%（資料未齊）")
					require.Contains(t, text, "建議升級的涵蓋情形 | 1.2.3 · 預計可處理此弱點")
					require.Contains(t, text, "建議升級的涵蓋情形 | 1.2.3 · 尚未確認涵蓋")
				} else {
					require.Contains(t, strings.Split(text, "\f")[0], "1. Verify immediately | urgent-package 1.0")
					require.Contains(t, strings.Split(text, "\f")[0], "Upgrade to test | 1.2.3")
					require.Contains(t, strings.Split(text, "\f")[0], "Cumulative findings expected to be addressed | 1")
					require.Contains(t, strings.Split(text, "\f")[0], "KEV findings still to address | CVE-2024-0002")
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
			require.NoError(t, Generate(&output, Report{Language: tc.language, SBOM: bom}))
			command := exec.Command(tool, "-layout", "-", "-")
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
			require.NoError(t, Generate(&output, report))
			require.True(t, bytes.HasPrefix(output.Bytes(), []byte("%PDF-1.4")))
			if tool, err := exec.LookPath("pdftotext"); err == nil {
				command := exec.Command(tool, "-layout", "-", "-")
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
	require.ErrorContains(t, Generate(failingWriter{}, Report{GeneratedAt: time.Now()}), "write failed")
}
