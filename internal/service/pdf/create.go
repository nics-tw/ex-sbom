// SPDX-License-Identifier: MIT

package pdf

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"ex-sbom/internal/domain"
	ssbom "ex-sbom/internal/service/sbom"

	"github.com/jung-kurt/gofpdf"
	"golang.org/x/image/font/sfnt"
)

// Noto Sans TC Regular is a static, BMP instance of the OFL-licensed upstream
// font (google/fonts Git blob 82943579ad39c281212df8f14ac999824694a6ab).
// It was generated with FontTools 4.61.1 at weight 400. The license is adjacent.
//
//go:embed fonts/NotoSansTC-Regular.ttf.gz
var compressedFont []byte

type reportFontData struct {
	bytes  []byte
	parsed *sfnt.Font
}

var loadFont = sync.OnceValues(func() (reportFontData, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressedFont))
	if err != nil {
		return reportFontData{}, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return reportFontData{}, err
	}
	parsed, err := sfnt.Parse(data)
	return reportFontData{bytes: data, parsed: parsed}, err
})

const (
	English            = "en"
	TraditionalChinese = "zh-Hant"
	reportFont         = "Noto Sans TC"
	margin             = 17.0
	lineHeight         = 5.1
)

func Language(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "zh", "zh-tw", "zh-hant":
		return TraditionalChinese
	default:
		return English
	}
}

func FileName(version string, createdAt time.Time) string {
	version = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), strings.ContainsRune(`<>:"/\|?*`, r):
			return '_'
		default:
			return r
		}
	}, version)
	version = strings.Trim(version, " .")
	version = strings.TrimSpace(version)
	runes := []rune(version)
	if len(runes) > 100 {
		version = string(runes[:100])
	}
	if version == "" {
		version = "sbom"
	}
	return fmt.Sprintf("%s_report_%s.pdf", version, createdAt.UTC().Format("20060102_150405"))
}

type Report struct {
	Project     domain.ProjectInfo
	Version     string
	GeneratedAt time.Time
	Language    string
	SBOM        ssbom.FormattedSBOM
}

type reportComponent struct {
	sbom  ssbom.Component
	scope string
}

type document struct {
	*gofpdf.Fpdf
	language      string
	font          *sfnt.Font
	fontBuffer    sfnt.Buffer
	glyphs        map[rune]bool
	width, bottom float64
	repeatHeading string
}

func Generate(w io.Writer, report Report) error {
	font, err := loadFont()
	if err != nil {
		return fmt.Errorf("load report font: %w", err)
	}
	pdf := gofpdf.New("P", "mm", "A4", "")
	width, height := pdf.GetPageSize()
	doc := &document{
		Fpdf: pdf, language: Language(report.Language), font: font.parsed,
		glyphs: make(map[rune]bool), width: width - 2*margin, bottom: height - margin - 2,
	}
	title := doc.label("Software Bill of Materials (SBOM) Analysis Report", "軟體物料清單（SBOM）分析報告")
	pdf.SetMargins(margin, margin, margin)
	pdf.SetAutoPageBreak(false, margin)
	pdf.SetCellMargin(0)
	pdf.AddUTF8FontFromBytes(reportFont, "", font.bytes)
	if err := pdf.Error(); err != nil {
		return fmt.Errorf("register report font: %w", err)
	}
	pdf.SetTitle(title, true)
	pdf.SetCreator("ex-sbom", true)
	pdf.SetCreationDate(report.GeneratedAt)
	pdf.SetHeaderFunc(func() {
		pdf.SetFont(reportFont, "", 8)
		pdf.SetTextColor(73, 92, 104)
		pdf.SetXY(margin, 9)
		pdf.CellFormat(doc.width, 5, "ex-sbom  |  "+doc.label("SBOM analysis", "SBOM 分析"), "", 0, "L", false, 0, "")
		pdf.SetDrawColor(205, 216, 220)
		pdf.Line(margin, 15, width-margin, 15)
		pdf.SetY(22)
	})
	pdf.SetFooterFunc(func() {
		pdf.SetDrawColor(205, 216, 220)
		pdf.Line(margin, height-14, width-margin, height-14)
		pdf.SetXY(margin, height-12)
		pdf.SetFont(reportFont, "", 8)
		pdf.SetTextColor(73, 92, 104)
		pdf.CellFormat(doc.width, 5, doc.label("Page ", "頁次 ")+strconv.Itoa(pdf.PageNo()), "", 0, "R", false, 0, "")
	})
	pdf.AddPage()

	doc.SetTextColor(20, 52, 66)
	doc.SetFont(reportFont, "", 19)
	doc.write(title, 9)
	doc.Ln(5)
	doc.section(doc.label("Report information", "報告資訊"))
	doc.field(doc.label("Project", "專案"), report.Project.Name)
	doc.field(doc.label("Project ID", "專案識別碼"), strconv.FormatInt(report.Project.ID, 10))
	doc.field(doc.label("Version", "版本"), report.Version)
	source := report.SBOM.ReportSource
	if source == nil {
		source = &ssbom.ReportSource{}
	}
	doc.field(doc.label("Source file", "來源檔案"), source.FileName)
	doc.field(doc.label("SBOM specification", "SBOM 規格"), source.Specification)
	doc.field(doc.label("Source file SHA-256", "來源檔案 SHA-256"), source.FileSHA256)
	doc.field(doc.label("Generated at (UTC)", "產製時間（UTC）"), report.GeneratedAt.UTC().Format("2006-01-02 15:04:05"))
	if source.QueriedAt != nil && !source.QueriedAt.IsZero() {
		doc.field(doc.label("Query observed at (UTC)", "查詢時間（UTC）"), source.QueriedAt.UTC().Format("2006-01-02 15:04:05"))
	}

	components := sortedComponents(report.SBOM)
	var findings, direct, transitive, unknown, affected, directAffected, transitiveAffected int
	var severities [6]int
	var epssBands, levBands [3]int
	for _, component := range components {
		findings += len(component.sbom.Vulns)
		if len(component.sbom.Vulns) > 0 {
			affected++
		}
		for _, vuln := range component.sbom.Vulns {
			severities[severity(vuln.CVSSScore)]++
			countRiskThresholds(&epssBands, vuln.EPSS)
			countRiskThresholds(&levBands, vuln.LEV)
		}
		switch component.scope {
		case "direct":
			direct++
			if len(component.sbom.Vulns) > 0 {
				directAffected++
			}
		case "transitive":
			transitive++
			if len(component.sbom.Vulns) > 0 {
				transitiveAffected++
			}
		default:
			unknown++
		}
	}

	doc.section(doc.label("Analysis summary", "分析摘要"))
	doc.field(doc.label("Vulnerability query status", "弱點查詢狀態"), doc.queryStatus(source.Status, findings))
	doc.field(doc.label("Components", "元件數"), strconv.Itoa(len(components)))
	doc.field(doc.label("Direct / Transitive / Unclassified", "直接／間接／未分類"), fmt.Sprintf("%d / %d / %d", direct, transitive, unknown))
	doc.field(doc.label("Components with findings", "有弱點紀錄的元件數"), strconv.Itoa(affected))
	doc.field(doc.label("Direct / transitive components with findings", "有弱點紀錄的直接／間接元件"), fmt.Sprintf("%d / %d", directAffected, transitiveAffected))
	doc.field(doc.label("Component-vulnerability findings", "元件弱點紀錄數"), strconv.Itoa(findings))
	doc.field(doc.label("CVSS critical / high / medium / low / none / unavailable", "CVSS 極高／高／中／低／無／未提供"),
		fmt.Sprintf("%d / %d / %d / %d / %d / %d", severities[5], severities[4], severities[3], severities[2], severities[1], severities[0]))
	doc.field("EPSS ≥ 10% / 50% / 90%", fmt.Sprintf("%d / %d / %d", epssBands[0], epssBands[1], epssBands[2]))
	doc.field("LEV ≥ 10% / 50% / 90%", fmt.Sprintf("%d / %d / %d", levBands[0], levBands[1], levBands[2]))
	doc.field(doc.label("Analysis scope", "分析範圍"), doc.label(
		"Findings are the records stored for this SBOM version. A finding shared by multiple components is counted for each component.",
		"本報告呈現此 SBOM 版本儲存的弱點紀錄。同一弱點涉及多個元件時，按元件分別計入。"))

	doc.componentTable(components)
	doc.vulnerabilityDetails(components)
	return pdf.Output(w)
}

func sortedComponents(bom ssbom.FormattedSBOM) []reportComponent {
	list := make(map[string]ssbom.Component, len(bom.ComponentInfo))
	for _, key := range bom.Components {
		list[key] = ssbom.Component{Name: key}
	}
	for key, c := range bom.ComponentInfo {
		if c.Name == "" {
			c.Name = key
		}
		list[key] = c
	}
	keys := slices.Sorted(maps.Keys(list))
	result := make([]reportComponent, 0, len(keys))
	for _, key := range keys {
		scope := "unknown"
		if level, ok := bom.ComponentToLevel[key]; ok {
			switch {
			case level == 0:
				scope = "direct"
			case level > 0:
				scope = "transitive"
			}
		}
		result = append(result, reportComponent{sbom: list[key], scope: scope})
	}
	return result
}

// Each threshold counts all findings at or above that probability.
func countRiskThresholds(counts *[3]int, value string) {
	score, err := strconv.ParseFloat(value, 64)
	if err != nil || score > 1 {
		return
	}
	for index, threshold := range [3]float64{0.1, 0.5, 0.9} {
		if score >= threshold {
			counts[index]++
		}
	}
}

func severity(value string) int {
	score, err := strconv.ParseFloat(value, 64)
	switch {
	case err != nil || math.IsNaN(score) || score < 0 || score > 10:
		return 0
	case score >= 9:
		return 5
	case score >= 7:
		return 4
	case score >= 4:
		return 3
	case score > 0:
		return 2
	default:
		return 1
	}
}

func (d *document) label(en, zh string) string {
	if d.language == TraditionalChinese {
		return zh
	}
	return en
}

func (d *document) queryStatus(status ssbom.QueryStatus, findings int) string {
	switch status {
	case ssbom.QueryCompleted:
		if findings == 0 {
			return d.label("Query completed. No known vulnerabilities found.", "查詢完成，未發現已知弱點")
		}
		return d.label("Query completed. Findings are listed below.", "查詢完成，已列出弱點紀錄")
	case ssbom.QueryPartial:
		return d.label("Query partially completed. Coverage or returned findings could not be fully confirmed.", "查詢部分完成，涵蓋範圍或回傳的弱點紀錄尚未完整確認")
	case ssbom.QueryNotRun:
		return d.label("No vulnerability query was performed.", "未執行弱點查詢")
	case ssbom.QueryFailed:
		return d.label("Vulnerability query failed.", "弱點查詢失敗")
	default:
		return d.label("Query status was not recorded.", "查詢狀態未記錄")
	}
}

func (d *document) section(title string) {
	d.ensureSpace(14)
	d.Ln(4)
	d.SetTextColor(20, 76, 88)
	d.SetFont(reportFont, "", 12)
	d.write(title, 6.5)
	d.SetTextColor(24, 37, 42)
	d.SetFont(reportFont, "", 9)
}

func (d *document) field(label, value string) {
	if value == "" {
		value = d.label("Not recorded", "未記錄")
	}
	d.write(label+"  |  "+value, lineHeight)
}

func (d *document) ensureSpace(height float64) {
	if d.GetY()+height <= d.bottom {
		return
	}
	d.AddPage()
	if d.repeatHeading != "" {
		d.section(d.repeatHeading)
	}
}

func (d *document) write(value string, height float64) {
	for _, line := range d.wrap(value, d.width) {
		d.ensureSpace(height)
		d.CellFormat(d.width, height, line, "", 1, "L", false, 0, "")
	}
}

// Keep each emitted line within its column. Escape unsupported characters
// visibly so identifiers can still be recovered and unsupported runes cannot
// trip the PDF library's BMP-only font implementation.
func (d *document) wrap(value string, width float64) []string {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\r", "\n")
	var lines []string
	for _, paragraph := range strings.Split(value, "\n") {
		var normalized strings.Builder
		for _, char := range paragraph {
			if char == '\t' {
				normalized.WriteString("    ")
				continue
			}
			supported, checked := d.glyphs[char]
			if !checked {
				index, err := d.font.GlyphIndex(&d.fontBuffer, char)
				supported = err == nil && index != 0 && char <= 0xffff && !unicode.IsControl(char) && !unicode.Is(unicode.Cf, char)
				d.glyphs[char] = supported
			}
			if supported {
				normalized.WriteRune(char)
			} else {
				fmt.Fprintf(&normalized, "[U+%04X]", char)
			}
		}
		text := []rune(normalized.String())
		if len(text) == 0 {
			lines = append(lines, "")
			continue
		}
		start, lastSpace, lineWidth := 0, -1, 0.0
		for i, char := range text {
			charWidth := d.GetStringWidth(string(char))
			if lineWidth+charWidth > width && i > start {
				end := i
				if lastSpace >= start {
					end = lastSpace + 1
				}
				lines = append(lines, strings.TrimRight(string(text[start:end]), " "))
				start = end
				lineWidth = d.GetStringWidth(string(text[start:i]))
				lastSpace = -1
				if lineWidth+charWidth > width && i > start {
					lines = append(lines, strings.TrimRight(string(text[start:i]), " "))
					start, lineWidth = i, 0
				}
			}
			if char == ' ' {
				lastSpace = i
			}
			lineWidth += charWidth
		}
		lines = append(lines, strings.TrimRight(string(text[start:]), " "))
	}
	return lines
}

func (d *document) componentTable(components []reportComponent) {
	title := d.label("Component inventory", "元件清單")
	d.ensureSpace(4 + 6.5 + 7 + lineHeight)
	d.section(title)
	if len(components) == 0 {
		d.write(d.label("No component records.", "沒有元件紀錄"), lineHeight)
		return
	}
	widths := []float64{96, 33, 23, d.width - 152}
	labels := []string{d.label("Component", "元件"), d.label("Version", "版本"), d.label("Scope", "類型"), d.label("Findings", "弱點數")}
	header := func() {
		d.SetFont(reportFont, "", 9)
		d.SetTextColor(20, 52, 66)
		d.SetFillColor(227, 239, 242)
		for i, label := range labels {
			d.CellFormat(widths[i], 7, label, "", 0, "L", true, 0, "")
		}
		d.Ln(7)
		d.SetTextColor(24, 37, 42)
	}
	header()
	for _, component := range components {
		scope := d.label("Unknown", "未分類")
		switch component.scope {
		case "direct":
			scope = d.label("Direct", "直接")
		case "transitive":
			scope = d.label("Transitive", "間接")
		}
		values := []string{component.sbom.Name, component.sbom.Version, scope, strconv.Itoa(len(component.sbom.Vulns))}
		lines := make([][]string, len(values))
		height := 1
		for i, value := range values {
			lines[i] = d.wrap(value, widths[i]-3)
			height = max(height, len(lines[i]))
		}
		for n := 0; n < height; n++ {
			if d.GetY()+lineHeight > d.bottom {
				d.AddPage()
				d.section(title)
				header()
			}
			for i := range values {
				value := ""
				if n < len(lines[i]) {
					value = lines[i][n]
				}
				d.CellFormat(widths[i], lineHeight, value, "", 0, "L", false, 0, "")
			}
			d.Ln(lineHeight)
		}
		d.SetDrawColor(227, 233, 236)
		d.Line(margin, d.GetY(), margin+d.width, d.GetY())
	}
}

func (d *document) vulnerabilityDetails(components []reportComponent) {
	title := d.label("Vulnerability details", "弱點明細")
	d.section(title)
	d.repeatHeading = title
	defer func() { d.repeatHeading = "" }()
	var count int
	for _, component := range components {
		for _, vulnerability := range component.sbom.Vulns {
			count++
			d.ensureSpace(3 * lineHeight)
			d.Ln(3)
			d.field(d.label("Component", "元件"), component.sbom.Name)
			d.field(d.label("Version", "版本"), component.sbom.Version)
			d.field(d.label("Vulnerability ID", "弱點識別碼"), vulnerability.ID)
			d.field(d.label("Summary", "摘要"), vulnerability.Summary)
			d.field("CVSS", vulnerability.CVSSScore)
			d.field("EPSS", vulnerability.EPSS)
			d.field("LEV", vulnerability.LEV)
			d.field(d.label("Suggested fix versions", "建議修補版本"), vulnerability.SuggestFixVersion)
			d.field(d.label("Other fix versions", "其他修補版本"), vulnerability.OtherFixVersions)
			d.field(d.label("Details", "詳細說明"), vulnerability.Details)
		}
	}
	if count == 0 {
		d.write(d.label("No vulnerability records stored for this version.", "此版本未儲存弱點紀錄"), lineHeight)
	}
}
