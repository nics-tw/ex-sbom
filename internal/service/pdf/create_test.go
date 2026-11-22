// SPDX-License-Identifier: MIT

//go:build unit

package pdf

import (
	"bytes"
	"errors"
	"os/exec"
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
				Vulns: []ssbom.Vuln{{ID: "TEST-EX-SBOM-0001", CVSSScore: "8.4",
					Summary: "弱點摘要", Details: strings.Repeat("跨頁內容 Mixed-language text. ", 400) + "末頁標記"}}},
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
				require.Contains(t, text, tc.count+" | 1")
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

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestGeneratePropagatesWriteFailure(t *testing.T) {
	require.ErrorContains(t, Generate(failingWriter{}, Report{GeneratedAt: time.Now()}), "write failed")
}
