// SPDX-License-Identifier: MIT

//go:build taggedpdf && ((darwin && !ios && arm64) || (linux && !android && (arm64 || amd64)) || (windows && amd64))

package pdf

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"ex-sbom/client/first"
	ssbom "ex-sbom/internal/service/sbom"
)

type taggedData struct {
	Title            string            `json:"title"`
	Language         string            `json:"language"`
	Metadata         []taggedField     `json:"metadata"`
	Evidence         []taggedField     `json:"evidence"`
	Summary          []taggedField     `json:"summary"`
	Warning          string            `json:"warning"`
	EmptyRemediation string            `json:"empty_remediation"`
	UrgentComponents string            `json:"urgent_components"`
	KEVCount         string            `json:"kev_count"`
	AdditionalUrgent string            `json:"additional_urgent"`
	NeedsReview      int               `json:"needs_review"`
	Actions          []taggedAction    `json:"actions"`
	OrderHeaders     []string          `json:"order_headers"`
	OrderRows        []reportTableRow  `json:"order_rows"`
	OrderNote        string            `json:"order_note"`
	Components       []taggedComponent `json:"components"`
	Findings         []taggedFinding   `json:"findings"`
	HasMissingGlyphs bool              `json:"has_missing_glyphs"`
}

type taggedField struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type taggedAction struct {
	Title           string        `json:"title"`
	Priority        string        `json:"priority"`
	Fields          []taggedField `json:"fields"`
	Residual        []string      `json:"residual"`
	Coverage        []string      `json:"coverage"`
	CumulativeCount int           `json:"cumulative_count"`
	FullCVECount    int           `json:"full_cve_count"`
	RemainingUrgent string        `json:"remaining_urgent"`
	CoverageNote    string        `json:"coverage_note"`
}

type taggedComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Scope   string `json:"scope"`
	Count   int    `json:"count"`
}

type taggedFinding struct {
	Title     string        `json:"title"`
	Component taggedField   `json:"component"`
	Version   taggedField   `json:"version"`
	Summary   taggedField   `json:"summary"`
	Fields    []taggedField `json:"fields"`
	Details   taggedField   `json:"details"`
}

func buildTaggedData(report Report) taggedData {
	d := &document{language: Language(report.Language)}
	label := d.label
	const utcLayout = "2006-01-02 15:04:05"
	threshold := ssbom.RemediationThreshold
	assessments := report.SBOM.RemediationAssessments(&threshold)
	source := report.SBOM.ReportSource
	if source == nil {
		source = &ssbom.ReportSource{}
	}
	components := sortedComponents(report.SBOM)
	kevCount, kevComplete, evidenceComplete := remediationEvidence(source, report.SBOM.ComponentInfo)
	data := taggedData{
		Title:        label("Software Bill of Materials (SBOM) Analysis Report", "軟體物料清單（SBOM）分析報告"),
		Language:     label("en", "zh"),
		OrderHeaders: d.remediationHeaders(),
		OrderRows:    d.remediationRows(assessments, report.SBOM.ComponentInfo),
		OrderNote:    d.remediationOrderNote(),
		Metadata: []taggedField{
			{label("Project", "專案"), report.Project.Name},
			{label("Version", "版本"), report.Version},
			{label("SBOM specification", "SBOM 規格"), source.Specification},
			{label("Vulnerability query status", "弱點查詢狀態"), d.queryStatus(source.Status, len(assessments))},
		},
		Evidence: []taggedField{
			{label("Project ID", "專案識別碼"), strconv.FormatInt(report.Project.ID, 10)},
			{label("Source file", "來源檔案"), source.FileName},
			{label("Source file SHA-256", "來源檔案 SHA-256"), source.FileSHA256},
			{label("Generated at (UTC)", "產製時間（UTC）"), report.GeneratedAt.UTC().Format(utcLayout)},
		},
		Actions:    make([]taggedAction, 0, len(assessments)),
		Components: make([]taggedComponent, 0, len(components)),
		Findings:   []taggedFinding{},
	}
	if source.QueriedAt != nil && !source.QueriedAt.IsZero() {
		data.Metadata = append(data.Metadata, taggedField{label("Query observed at (UTC)", "查詢時間（UTC）"), source.QueriedAt.UTC().Format(utcLayout)})
	}
	if source.KEVCheckedAt != nil {
		data.Evidence = append(data.Evidence,
			taggedField{label("CISA KEV catalog version", "CISA KEV 清單版本"), source.KEVCatalogVersion},
			taggedField{label("KEV checked at (UTC)", "KEV 查核時間（UTC）"), source.KEVCheckedAt.UTC().Format(utcLayout)},
		)
	}

	if len(assessments) == 0 {
		if source.Status == ssbom.QueryCompleted {
			data.EmptyRemediation = label("No remediation items for this query. See Component inventory for the packages in scope.", "本次無修補項目。元件與版本請見「元件清單」。")
		} else {
			data.EmptyRemediation = label("No remediation order established yet. Verify query coverage before deferring work.", "目前無法判定修補順序。請先查證弱點查詢範圍，再決定是否延後處理。")
		}
	} else if !evidenceComplete {
		data.Warning = label("Evidence incomplete. Review the analysis summary and KEV status before deciding what work can wait.", "部分資料仍待確認。決定哪些工作可延後前，請先核對分析摘要與 KEV 查核狀態。")
	}

	byComponent := make(map[string]ssbom.ComponentAssessment, len(assessments))
	urgentComponents := 0
	for i, entry := range assessments {
		byComponent[entry.Key] = entry
		action := d.taggedRemediationAction(i+1, entry, report.SBOM.ComponentToLevel)
		action.RemainingUrgent = d.urgencyCount(entry.RemainingUrgent, evidenceComplete)
		data.Actions = append(data.Actions, action)
		if entry.Driver.Priority == ssbom.RemediationUrgent {
			urgentComponents++
		}
		if entry.NeedsReview > 0 {
			data.NeedsReview++
		}
	}
	data.UrgentComponents = d.urgencyCount(urgentComponents, evidenceComplete)
	data.KEVCount = d.urgencyCount(kevCount, kevComplete)
	if urgentComponents > 1 {
		data.AdditionalUrgent = d.urgencyCount(urgentComponents-1, evidenceComplete)
	}

	var severities [6]int
	var epssBands, levBands [3]int
	var affected, direct, transitive, unknown, directAffected, transitiveAffected, unavailableLEV int
	for _, component := range components {
		count := len(component.sbom.Vulns)
		if count > 0 {
			affected++
		}
		scope := label("Unknown", "未分類")
		switch component.scope {
		case "direct":
			scope = label("Direct", "直接")
			direct++
			if count > 0 {
				directAffected++
			}
		case "transitive":
			scope = label("Transitive", "間接")
			transitive++
			if count > 0 {
				transitiveAffected++
			}
		default:
			unknown++
		}
		data.Components = append(data.Components, taggedComponent{
			Name:    component.sbom.Name,
			Version: component.sbom.Version,
			Scope:   scope,
			Count:   count,
		})
		assessment := byComponent[component.key]
		isGo := ssbom.IsGoComponent(source, component.key, component.sbom)
		for i, vuln := range component.sbom.Vulns {
			if isGo {
				vuln = vuln.GoAdvisoryDisplay()
			}
			severities[severity(vuln.CVSSScore)]++
			countRiskThresholds(&epssBands, vuln.EPSS)
			if _, valid := vuln.VerifiedLEV(); valid {
				countRiskThresholds(&levBands, vuln.LEV)
			} else {
				unavailableLEV++
			}
			data.Findings = append(data.Findings, d.taggedVulnerability(component, assessment, i, vuln, source))
		}
	}
	data.Summary = []taggedField{
		{label("Vulnerability query status", "弱點查詢狀態"), d.queryStatus(source.Status, len(data.Findings))},
		{label("Components", "元件數"), strconv.Itoa(len(components))},
		{label("Direct / Transitive / Unclassified", "直接／間接／未分類"), fmt.Sprintf("%d / %d / %d", direct, transitive, unknown)},
		{label("Components with findings", "有弱點紀錄的元件數"), strconv.Itoa(affected)},
		{label("Direct / transitive components with findings", "有弱點紀錄的直接／間接元件"), fmt.Sprintf("%d / %d", directAffected, transitiveAffected)},
		{label("Component-vulnerability findings", "元件弱點紀錄數"), strconv.Itoa(len(data.Findings))},
		{label("CVSS critical / high / medium / low / none / unavailable", "CVSS 極高／高／中／低／無／未提供"), fmt.Sprintf("%d / %d / %d / %d / %d / %d", severities[5], severities[4], severities[3], severities[2], severities[1], severities[0])},
		{"EPSS ≥ 10% / 50% / 90%", fmt.Sprintf("%d / %d / %d", epssBands[0], epssBands[1], epssBands[2])},
	}
	if source.LEVDisabled() {
		data.Summary = append(data.Summary, taggedField{"LEV", label("Disabled at scan time", "掃描時未啟用")})
	} else {
		data.Summary = append(data.Summary, taggedField{"LEV ≥ 10% / 50% / 90%", fmt.Sprintf("%d / %d / %d", levBands[0], levBands[1], levBands[2])})
		if unavailableLEV > 0 {
			data.Summary = append(data.Summary, taggedField{label("LEV unavailable or unverified", "LEV 未取得或未驗證"), strconv.Itoa(unavailableLEV)})
		}
	}
	data.Summary = append(data.Summary, taggedField{
		label("Analysis scope", "分析範圍"),
		label("Findings are the records stored for this SBOM version. A finding shared by multiple components is counted for each component.", "本報告呈現此 SBOM 版本儲存的弱點紀錄。同一弱點涉及多個元件時，按元件分別計入。"),
	})
	if len(assessments) > 0 {
		data.Summary = append(data.Summary,
			taggedField{label("Ranking policy", "排序規則"), d.remediationPolicy()},
			taggedField{label("Repair version policy", "修補版本選擇"), d.repairVersionPolicy()},
			taggedField{label("Exploitation signal calculation", "綜合利用指標算法"), d.exploitationMethod()},
		)
	}
	data.Summary = append(data.Summary, taggedField{
		label("Review notes", "查核說明"),
		d.reviewNotes(),
	})
	return data
}

func (d *document) taggedRemediationAction(rank int, entry ssbom.ComponentAssessment, levels map[string]int) taggedAction {
	label := d.label
	homepage := rank == 1
	urgent := entry.Driver.Priority == ssbom.RemediationUrgent
	priority := d.remediationPriorityLabel(entry.Driver.Priority)
	priorityStyle := "ordinary"
	switch entry.Driver.Priority {
	case ssbom.RemediationUrgent:
		priorityStyle = "urgent"
	case ssbom.RemediationElevated:
		priorityStyle = "elevated"
	}

	action := taggedAction{
		Title:           fmt.Sprintf("%d. %s | %s", rank, priority, strings.TrimSpace(entry.Name+" "+entry.Version)),
		Priority:        priorityStyle,
		Fields:          []taggedField{},
		Residual:        append([]string{}, entry.ResidualUrgentCVEs...),
		Coverage:        []string{},
		CumulativeCount: entry.CumulativeCovered,
		FullCVECount:    entry.CumulativeFullyCoveredCVEs,
	}
	if rank == 1 && entry.Upgrade == "" {
		action.CoverageNote = d.pendingRemediationCoverage()
	}
	field := func(name, value string) {
		action.Fields = append(action.Fields, taggedField{name, value})
	}
	if entry.Package != "" {
		field(label("Package identity", "套件識別"), entry.Ecosystem+" · "+entry.Package)
	}
	finding := entry.Driver.Finding
	score := finding.CVSSScore
	if !entry.Driver.HasCVSS {
		score = label("Unavailable", "未取得")
	}
	signal := d.exploitationValue(entry.Driver.Signal)
	if homepage && urgent {
		signal = label("Known exploitation (CISA KEV)", "已知遭利用（CISA KEV）")
	}
	field(label("Basis", "依據"), finding.ID+" · CVSS "+score+" · "+signal)
	if len(entry.UrgentCVEs) > 0 {
		field(label("Listed by CISA KEV", "列入 CISA KEV"), d.remediationKEVList(entry.UrgentCVEs, homepage))
	}
	if entry.Upgrade != "" {
		field(label("Upgrade to test", "建議驗測版本"), entry.Upgrade)
		for _, id := range entry.UrgentCVEs {
			if !slices.Contains(entry.ResidualUrgentCVEs, id) {
				action.Coverage = append(action.Coverage, id)
			}
		}
		if len(action.Coverage) > 0 {
			field(label("KEV findings expected to be addressed", "預計涵蓋的 KEV 弱點"), d.remediationKEVList(action.Coverage, homepage))
		}
	} else {
		field(label("Common fix version", "共同修補版本"),
			label("Unverified. See individual advisory candidates in the details.", "尚未驗證，個別公告候選請見弱點明細。"))
	}
	if len(action.Residual) > 0 {
		residualLabel := label("KEV findings still to address", "仍待處理的 KEV 弱點")
		if entry.Upgrade != "" {
			residualLabel = label("KEV findings without confirmed coverage in this version", "此版本未確認涵蓋的 KEV 弱點")
		}
		field(residualLabel, d.remediationKEVList(action.Residual, homepage))
	}

	next := label("Check advisory candidates and assess mitigations.", "查證公告候選版本，並評估緩解措施。")
	if entry.Upgrade != "" {
		next = label("Test the candidate, then confirm coverage with a new SBOM scan.", "驗測候選版本，再以新版 SBOM 複掃確認。")
	}
	if levels[entry.Key] > 0 {
		next = label("Identify the parent dependency and check its upgrade or lockfile. Confirm with a new SBOM scan.", "確認上游相依元件，檢查其升級方式或鎖定檔，再以新版 SBOM 複掃確認。")
	}
	if homepage && urgent {
		next = label("Confirm actual deployment and exposure. ", "確認實際部署與曝險。") + next
	}
	if entry.Driver.KEVMatch && strings.TrimSpace(entry.Version) == "" {
		next = d.confirmInstalledVersionAction()
	}
	field(label("Next action", "下一步"), next)
	return action
}

func (d *document) taggedVulnerability(component reportComponent, assessment ssbom.ComponentAssessment, i int, vuln ssbom.Vuln, source *ssbom.ReportSource) taggedFinding {
	label := d.label
	finding := taggedFinding{
		Title:     vuln.ID + " · " + strings.TrimSpace(component.sbom.Name+" "+component.sbom.Version),
		Component: taggedField{label("Component", "元件"), component.sbom.Name},
		Version:   taggedField{label("Version", "版本"), component.sbom.Version},
		Summary:   taggedField{label("Summary", "摘要"), vuln.Summary},
		Details:   taggedField{label("Details", "詳細說明"), vuln.Details},
		Fields: []taggedField{
			{"CVSS", vuln.CVSSScore},
			{label("CVSS version", "CVSS 指標版本"), vuln.CVSSVersion},
			{label("EPSS score date", "EPSS 評分日期"), vuln.EPSSDate},
		},
	}
	field := func(name, value string) {
		finding.Fields = append(finding.Fields, taggedField{name, value})
	}
	epss := ""
	if score, valid := first.ParseProbability(vuln.EPSS); valid {
		epss = probabilityPercent(score)
	}
	if epss != "" && vuln.EPSSPartial {
		epss = fmt.Sprintf(label("At least %s (missing alias scores)", "至少 %s（別名分數未齊）"), epss)
	}
	field("EPSS", epss)
	if vuln.EPSSCVE != "" && vuln.EPSSCVE != vuln.ID {
		field(label("EPSS source CVE", "EPSS 來源 CVE"), vuln.EPSSCVE)
	}

	if score, valid := vuln.VerifiedLEV(); valid {
		value := probabilityPercent(score)
		if vuln.LEVPartial {
			value = fmt.Sprintf(label("At least %s (historical gaps)", "至少 %s（歷史資料有缺口）"), value)
		}
		field("LEV", value)
		if vuln.LEVCVE != "" && vuln.LEVCVE != vuln.ID {
			field(label("LEV source CVE", "LEV 來源 CVE"), vuln.LEVCVE)
		}
		field(label("LEV calculation method", "LEV 計算方法"), vuln.LEVMethod)
		if vuln.LEVFirst != "" && vuln.LEVAsOf != "" {
			field(label("LEV period (UTC)", "LEV 歷史期間（UTC）"), vuln.LEVFirst+" – "+vuln.LEVAsOf)
		}
	} else if !source.LEVDisabled() {
		field("LEV", label("Unavailable or unverified", "未取得或未驗證"))
	}
	kev, kevIDs := vuln.KEVEvidence()
	field(label("Exploitation signal", "綜合利用指標"), d.exploitationValue(vuln.ExploitationSignal(kev, source)))
	switch kev {
	case ssbom.KEVListed:
		field("KEV", label("Listed in CISA catalog", "已列入 CISA 清單")+" · "+strings.Join(kevIDs, ", "))
	case ssbom.KEVUnlisted:
		field("KEV", label("Checked, not listed", "已查核，未列入"))
	default:
		field("KEV", label("Not checked", "尚未查核"))
	}
	if assessment.Upgrade != "" {
		coverage := label("Coverage not established", "尚未確認涵蓋")
		if assessment.CoveredFindings[i] {
			coverage = label("Expected to address this finding", "預計可處理此弱點")
		}
		field(label("Coverage of proposed upgrade", "建議升級的涵蓋情形"), assessment.Upgrade+" · "+coverage)
	}
	field(label("Advisory candidates for this finding", "此弱點的公告修補候選"), vuln.SuggestFixVersion)
	if vuln.OtherFixVersions != "" {
		field(label("Other advisory candidates", "其他公告候選版本"), vuln.OtherFixVersions)
	}
	return finding
}
