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
	"unicode/utf16"

	"ex-sbom/client/first"
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
	key   string
	sbom  ssbom.Component
	scope string
}

type document struct {
	*gofpdf.Fpdf
	language          string
	font              *sfnt.Font
	fontBuffer        sfnt.Buffer
	glyphs            map[rune]bool
	width, bottom     float64
	repeatHeading     string
	usedGlyphFallback bool
}

func Generate(w io.Writer, report Report) error {
	return generateUntagged(w, report)
}

func generateUntagged(w io.Writer, report Report) error {
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
	// ActualText requires PDF 1.4. Normal, fully opaque blending makes gofpdf
	// emit that version without changing the appearance of the report.
	pdf.SetAlpha(1, "Normal")

	doc.SetTextColor(20, 52, 66)
	doc.SetFont(reportFont, "", 19)
	doc.write(title, 9)
	doc.Ln(5)
	threshold := ssbom.RemediationThreshold
	assessments := report.SBOM.RemediationAssessments(&threshold)
	source := report.SBOM.ReportSource
	if source == nil {
		source = &ssbom.ReportSource{}
	}
	doc.SetFont(reportFont, "", 9)
	doc.SetTextColor(24, 37, 42)
	doc.field(doc.label("Project", "專案"), report.Project.Name)
	doc.field(doc.label("Version", "版本"), report.Version)
	doc.field(doc.label("SBOM specification", "SBOM 規格"), source.Specification)
	doc.field(doc.label("Vulnerability query status", "弱點查詢狀態"), doc.queryStatus(source.Status, len(assessments)))
	if source.QueriedAt != nil && !source.QueriedAt.IsZero() {
		doc.field(doc.label("Query observed at (UTC)", "查詢時間（UTC）"), source.QueriedAt.UTC().Format("2006-01-02 15:04:05"))
	}
	kevCount, kevComplete, evidenceComplete := remediationEvidence(source, report.SBOM.ComponentInfo)
	continuationLink := doc.remediationSummary(assessments, report.SBOM.ComponentToLevel, source, doc.urgencyCount(kevCount, kevComplete), evidenceComplete)
	if continuationLink != 0 {
		doc.remediationContinuation(assessments, report.SBOM, continuationLink, evidenceComplete)
	}

	doc.section(doc.label("Report information", "報告資訊"))
	doc.field(doc.label("Project ID", "專案識別碼"), strconv.FormatInt(report.Project.ID, 10))
	doc.field(doc.label("Source file", "來源檔案"), source.FileName)
	doc.field(doc.label("Source file SHA-256", "來源檔案 SHA-256"), source.FileSHA256)
	doc.field(doc.label("Generated at (UTC)", "產製時間（UTC）"), report.GeneratedAt.UTC().Format("2006-01-02 15:04:05"))

	if source.KEVCheckedAt != nil {
		doc.field(doc.label("CISA KEV catalog version", "CISA KEV 清單版本"), source.KEVCatalogVersion)
		doc.field(doc.label("KEV checked at (UTC)", "KEV 查核時間（UTC）"), source.KEVCheckedAt.UTC().Format("2006-01-02 15:04:05"))
	}

	components := sortedComponents(report.SBOM)
	var findings, direct, transitive, unknown, affected, directAffected, transitiveAffected int
	var severities [6]int
	var epssBands, levBands [3]int
	var unavailableLEV int
	for _, component := range components {
		findings += len(component.sbom.Vulns)
		if len(component.sbom.Vulns) > 0 {
			affected++
		}
		for _, vuln := range component.sbom.Vulns {
			severities[severity(vuln.CVSSScore)]++
			countRiskThresholds(&epssBands, vuln.EPSS)
			if _, valid := vuln.VerifiedLEV(); valid {
				countRiskThresholds(&levBands, vuln.LEV)
			} else {
				unavailableLEV++
			}
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
	if source.LEVDisabled() {
		doc.field("LEV", doc.label("Disabled at scan time", "掃描時未啟用"))
	} else {
		doc.field("LEV ≥ 10% / 50% / 90%", fmt.Sprintf("%d / %d / %d", levBands[0], levBands[1], levBands[2]))
		if unavailableLEV > 0 {
			doc.field(doc.label("LEV unavailable or unverified", "LEV 未取得或未驗證"), strconv.Itoa(unavailableLEV))
		}
	}
	doc.field(doc.label("Analysis scope", "分析範圍"), doc.label(
		"Findings are the records stored for this SBOM version. A finding shared by multiple components is counted for each component.",
		"本報告呈現此 SBOM 版本儲存的弱點紀錄。同一弱點涉及多個元件時，按元件分別計入。"))

	if len(assessments) != 0 {
		doc.field(doc.label("Ranking policy", "排序規則"), doc.remediationPolicy())
		doc.field(doc.label("Repair version policy", "修補版本選擇"), doc.repairVersionPolicy())
		doc.field(doc.label("Exploitation signal calculation", "綜合利用指標算法"), doc.exploitationMethod())
	}
	doc.field(doc.label("Review notes", "查核說明"), doc.reviewNotes())

	doc.componentTable(components)
	doc.vulnerabilityDetails(components, assessments, source)
	if doc.usedGlyphFallback {
		doc.section(doc.label("Text display note", "文字顯示說明"))
		doc.write(doc.label(
			"Some characters are displayed as Unicode code points. The original text is available for search and copy in compatible PDF readers.",
			"部分字元以 Unicode 碼位顯示。支援此功能的 PDF 閱讀器可搜尋及複製原文。"), lineHeight)
	}
	return pdf.Output(w)
}

func (d *document) reviewNotes() string {
	return d.label(
		"Confirm actual deployment and exposure with the operations team. Verify findings with insufficient evidence.",
		"請維運單位確認實際部署與曝險。證據不足的弱點仍待查證。",
	)
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
		result = append(result, reportComponent{key: key, sbom: list[key], scope: scope})
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
		d.textCell(d.width, height, line, 1)
	}
}

type textLine struct {
	display string
	actual  string
}

func (d *document) textCell(width, height float64, line textLine, newline int) {
	if line.actual != "" {
		// gofpdf can only draw characters in the BMP. PDF ActualText associates
		// the visible substitute with the original Unicode text.
		var encoded strings.Builder
		encoded.WriteString("/Span << /ActualText <FEFF")
		for _, unit := range utf16.Encode([]rune(line.actual)) {
			fmt.Fprintf(&encoded, "%04X", unit)
		}
		encoded.WriteString("> >> BDC")
		d.RawWriteStr(encoded.String())
	}
	d.CellFormat(width, height, line.display, "", newline, "L", false, 0, "")
	if line.actual != "" {
		d.RawWriteStr("EMC")
	}
}

// Keep each emitted line within its column without splitting a code point's
// visible substitute. Controls and format characters stay escaped when copied.
func (d *document) wrap(value string, width float64) []textLine {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\r", "\n")
	var lines []textLine
	for _, paragraph := range strings.Split(value, "\n") {
		paragraph = strings.ReplaceAll(paragraph, "\t", "    ")
		var characters []textLine
		for _, char := range paragraph {
			characters = append(characters, d.displayCharacter(char))
		}
		start, lastSpace, lineWidth := 0, -1, 0.0
		for i, character := range characters {
			charWidth := d.GetStringWidth(character.display)
			if lineWidth+charWidth > width && i > start {
				end := i
				if lastSpace >= start {
					end = lastSpace + 1
				}
				lines = append(lines, joinTextLine(characters[start:end]))
				start = end
				lineWidth, lastSpace = 0, -1
				for _, remaining := range characters[start:i] {
					lineWidth += d.GetStringWidth(remaining.display)
				}
				if lineWidth+charWidth > width && i > start {
					lines = append(lines, joinTextLine(characters[start:i]))
					start, lineWidth = i, 0
				}
			}
			if character.display == " " {
				lastSpace = i
			}
			lineWidth += charWidth
		}
		lines = append(lines, joinTextLine(characters[start:]))
	}
	return lines
}

func (d *document) displayCharacter(char rune) textLine {
	if unicode.IsControl(char) || unicode.Is(unicode.Cf, char) {
		return textLine{display: fmt.Sprintf("[U+%04X]", char)}
	}
	supported, checked := d.glyphs[char]
	if !checked {
		index, err := d.font.GlyphIndex(&d.fontBuffer, char)
		supported = err == nil && index != 0 && char <= 0xffff
		d.glyphs[char] = supported
	}
	if supported {
		return textLine{display: string(char)}
	}
	d.usedGlyphFallback = true
	return textLine{display: fmt.Sprintf("[U+%04X]", char), actual: string(char)}
}

func joinTextLine(characters []textLine) textLine {
	var display, actual strings.Builder
	hasFallback := false
	for _, character := range characters {
		display.WriteString(character.display)
		if character.actual == "" {
			actual.WriteString(character.display)
		} else {
			actual.WriteString(character.actual)
			hasFallback = true
		}
	}
	line := textLine{display: strings.TrimRight(display.String(), " ")}
	if hasFallback {
		line.actual = strings.TrimRight(actual.String(), " ")
	}
	return line
}

func (d *document) componentTable(components []reportComponent) {
	title := d.label("Component inventory", "元件清單")
	if len(components) == 0 {
		d.section(title)
		d.write(d.label("No component records.", "沒有元件紀錄"), lineHeight)
		return
	}
	rows := make([]reportTableRow, 0, len(components))
	for _, component := range components {
		scope := d.label("Unknown", "未分類")
		switch component.scope {
		case "direct":
			scope = d.label("Direct", "直接")
		case "transitive":
			scope = d.label("Transitive", "間接")
		}
		rows = append(rows, reportTableRow{
			Cells: []string{component.sbom.Name, component.sbom.Version, scope, strconv.Itoa(len(component.sbom.Vulns))},
		})
	}
	d.reportTable(title, "", []float64{96, 33, 23, d.width - 152},
		[]string{d.label("Component", "元件"), d.label("Version", "版本"), d.label("Scope", "類型"), d.label("Findings", "弱點數")}, rows, -1)
}

type reportTableRow struct {
	Cells  []string `json:"cells"`
	Urgent bool     `json:"urgent"`
}

func (d *document) reportTable(title, note string, widths []float64, labels []string, rows []reportTableRow, urgentColumn int) {
	d.ensureSpace(4 + 6.5 + 7 + lineHeight)
	d.section(title)
	if note != "" {
		d.write(note, lineHeight)
		d.Ln(2)
	}
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
	for _, row := range rows {
		values := row.Cells
		lines := make([][]textLine, len(values))
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
				var value textLine
				if n < len(lines[i]) {
					value = lines[i][n]
				}
				if i == urgentColumn && row.Urgent {
					d.SetTextColor(128, 26, 36)
				}
				d.textCell(widths[i], lineHeight, value, 0)
				if i == urgentColumn && row.Urgent {
					d.SetTextColor(24, 37, 42)
				}
			}
			d.Ln(lineHeight)
		}
		d.SetDrawColor(227, 233, 236)
		d.Line(margin, d.GetY(), margin+d.width, d.GetY())
	}
}

func (d *document) vulnerabilityDetails(components []reportComponent, assessments []ssbom.ComponentAssessment, source *ssbom.ReportSource) {
	byComponent := make(map[string]ssbom.ComponentAssessment, len(assessments))
	for _, entry := range assessments {
		byComponent[entry.Key] = entry
	}
	title := d.label("Vulnerability details", "弱點明細")
	d.section(title)
	d.repeatHeading = title
	defer func() { d.repeatHeading = "" }()
	var count int
	for _, component := range components {
		assessment := byComponent[component.key]
		isGo := ssbom.IsGoComponent(source, component.key, component.sbom)
		for i, vulnerability := range component.sbom.Vulns {
			if isGo {
				vulnerability = vulnerability.GoAdvisoryDisplay()
			}
			count++
			d.ensureSpace(3 * lineHeight)
			d.Ln(3)
			d.field(d.label("Component", "元件"), component.sbom.Name)
			d.field(d.label("Version", "版本"), component.sbom.Version)
			d.field(d.label("Vulnerability ID", "弱點識別碼"), vulnerability.ID)
			d.field(d.label("Summary", "摘要"), vulnerability.Summary)
			d.field("CVSS", vulnerability.CVSSScore)
			d.field(d.label("CVSS version", "CVSS 指標版本"), vulnerability.CVSSVersion)
			d.field(d.label("EPSS score date", "EPSS 評分日期"), vulnerability.EPSSDate)
			epss := ""
			if score, valid := first.ParseProbability(vulnerability.EPSS); valid {
				epss = probabilityPercent(score)
			}
			if epss != "" && vulnerability.EPSSPartial {
				epss = fmt.Sprintf(d.label("At least %s (missing alias scores)", "至少 %s（別名分數未齊）"), epss)
			}
			d.field("EPSS", epss)
			if vulnerability.EPSSCVE != "" && vulnerability.EPSSCVE != vulnerability.ID {
				d.field(d.label("EPSS source CVE", "EPSS 來源 CVE"), vulnerability.EPSSCVE)
			}
			if score, valid := vulnerability.VerifiedLEV(); valid {
				value := probabilityPercent(score)
				if vulnerability.LEVPartial {
					value = fmt.Sprintf(d.label("At least %s (historical gaps)", "至少 %s（歷史資料有缺口）"), value)
				}
				d.field("LEV", value)
				if vulnerability.LEVCVE != "" && vulnerability.LEVCVE != vulnerability.ID {
					d.field(d.label("LEV source CVE", "LEV 來源 CVE"), vulnerability.LEVCVE)
				}
				d.field(d.label("LEV calculation method", "LEV 計算方法"), vulnerability.LEVMethod)
				if vulnerability.LEVFirst != "" && vulnerability.LEVAsOf != "" {
					d.field(d.label("LEV period (UTC)", "LEV 歷史期間（UTC）"), vulnerability.LEVFirst+" – "+vulnerability.LEVAsOf)
				}
			} else if !source.LEVDisabled() {
				d.field("LEV", d.label("Unavailable or unverified", "未取得或未驗證"))
			}
			kev, kevIDs := vulnerability.KEVEvidence()
			d.field(d.label("Exploitation signal", "綜合利用指標"), d.exploitationValue(vulnerability.ExploitationSignal(kev, source)))
			switch kev {
			case ssbom.KEVListed:
				d.field("KEV", d.label("Listed in CISA catalog", "已列入 CISA 清單")+" · "+strings.Join(kevIDs, ", "))
			case ssbom.KEVUnlisted:
				d.field("KEV", d.label("Checked, not listed", "已查核，未列入"))
			default:
				d.field("KEV", d.label("Not checked", "尚未查核"))
			}
			if assessment.Upgrade != "" {
				coverage := d.label("Coverage not established", "尚未確認涵蓋")
				if assessment.CoveredFindings[i] {
					coverage = d.label("Expected to address this finding", "預計可處理此弱點")
				}
				d.field(d.label("Coverage of proposed upgrade", "建議升級的涵蓋情形"), assessment.Upgrade+" · "+coverage)
			}
			d.field(d.label("Advisory candidates for this finding", "此弱點的公告修補候選"), vulnerability.SuggestFixVersion)
			if vulnerability.OtherFixVersions != "" {
				d.field(d.label("Other advisory candidates", "其他公告候選版本"), vulnerability.OtherFixVersions)
			}
			d.field(d.label("Details", "詳細說明"), vulnerability.Details)
		}
	}
	if count == 0 {
		d.write(d.label("No vulnerability records stored for this version.", "此版本未儲存弱點紀錄"), lineHeight)
	}
}
