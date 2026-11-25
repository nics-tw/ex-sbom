// SPDX-License-Identifier: MIT

package pdf

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"ex-sbom/client/cisa"
	ssbom "ex-sbom/internal/service/sbom"
)

// remediationMetrics shows component and CVE counts separately. The count
// follows its label in the document's text order.
func (d *document) remediationMetrics(urgent, kev string) {
	const gap, padding, height = 4.0, 3.0, 22.0
	d.ensureSpace(height + 2)
	width := (d.width - gap) / 2
	y := d.GetY()
	for i, metric := range []struct {
		label string
		count string
	}{
		{d.label("Components to update immediately", "需立即更新的元件"), urgent},
		{d.label("CVEs listed in CISA KEV", "列入 CISA KEV 的弱點"), kev},
	} {
		x := margin + float64(i)*(width+gap)
		d.SetFillColor(238, 242, 243)
		d.Rect(x, y, width, height, "F")
		d.SetFont(reportFont, "", 10)
		d.SetXY(x+padding, y+padding)
		d.CellFormat(width-2*padding, 6, metric.label, "", 0, "L", false, 0, "")
		d.SetFont(reportFont, "", 16)
		d.SetXY(x+padding, y+padding+7)
		d.CellFormat(width-2*padding, 8, metric.count, "", 0, "L", false, 0, "")
	}
	d.SetFont(reportFont, "", 9)
	d.SetXY(margin, y+height+2)
}

// remediationCardField keeps labels and values aligned in the first action.
// A very long row can use the normal page-aware writer.
func (d *document) remediationCardField(label, value string) {
	const padding, labelWidth = 5.0, 57.0
	if value == "" {
		value = d.label("Not recorded", "未記錄")
	}
	labels := d.wrap(label, labelWidth-3)
	values := d.wrap(value, d.width-labelWidth-2*padding-2)
	height := float64(max(len(labels), len(values))) * lineHeight
	if d.GetY()+height+3 > d.bottom {
		d.field(label, value)
		return
	}
	y := d.GetY()
	for i, line := range labels {
		d.SetXY(margin+padding, y+float64(i)*lineHeight)
		d.textCell(labelWidth, lineHeight, line, 0)
	}
	for i, line := range values {
		d.SetXY(margin+padding+labelWidth, y+float64(i)*lineHeight)
		d.textCell(d.width-labelWidth-2*padding, lineHeight, line, 0)
	}
	d.SetXY(margin, y+height+1)
}

func remediationEvidence(source *ssbom.ReportSource, components map[string]ssbom.Component) (kevCount int, kevComplete, urgencyComplete bool) {
	kevComplete = source.Status == ssbom.QueryCompleted
	versionKnown := true
	listed := make(map[string]struct{})
	for _, component := range components {
		for _, finding := range component.Vulns {
			if len(finding.CVEIDs) == 0 {
				if cisa.IsCVE(finding.ID) {
					kevComplete = false
				}
				continue
			}
			kev, ids := finding.KEVEvidence()
			if source.KEVCheckedAt == nil || (kev != ssbom.KEVListed && kev != ssbom.KEVUnlisted) {
				kevComplete = false
			}
			if kev != ssbom.KEVListed {
				continue
			}
			for _, id := range ids {
				listed[id] = struct{}{}
			}
			versionKnown = versionKnown && component.ConfirmedInstalledVersion() != ""
		}
	}
	return len(listed), kevComplete, kevComplete && versionKnown
}

func (d *document) urgencyCount(count int, evidenceComplete bool) string {
	value := strconv.Itoa(count)
	if evidenceComplete {
		return value
	}
	if count == 0 {
		return d.label("Pending", "待查證")
	}
	return d.label("At least ", "至少 ") + value
}

func (d *document) pendingRemediationCoverage() string {
	return d.label(
		"Coverage is pending. Test a fix and rescan to confirm what it addresses.",
		"涵蓋範圍待確認。需驗測修補版本並複掃後，才能確認處理結果。",
	)
}

func (d *document) remediationSummary(entries []ssbom.ComponentAssessment, levels map[string]int, source *ssbom.ReportSource, kevCount string, evidenceComplete bool) int {
	d.section(d.label("Remediation summary", "修補摘要"))
	if len(entries) == 0 {
		if source.Status == ssbom.QueryCompleted {
			d.write(d.label(
				"No remediation items for this query. See Component inventory for the packages in scope.",
				"本次無修補項目。元件與版本請見「元件清單」。"), lineHeight)
		} else {
			d.write(d.label(
				"No remediation order established yet. Verify query coverage before deferring work.",
				"目前無法判定修補順序。請先查證弱點查詢範圍，再決定是否延後處理。"), lineHeight)
		}
		return 0
	}
	if !evidenceComplete {
		d.write(d.label(
			"Evidence incomplete. Review the analysis summary and KEV status before deciding what work can wait.",
			"部分資料仍待確認。決定哪些工作可延後前，請先核對分析摘要與 KEV 查核狀態。"), lineHeight)
	}

	urgent, review := 0, 0
	for _, entry := range entries {
		if entry.Driver.Priority == ssbom.RemediationUrgent {
			urgent++
		}
		if entry.NeedsReview > 0 {
			review++
		}
	}
	d.remediationMetrics(d.urgencyCount(urgent, evidenceComplete), kevCount)
	if review != 0 {
		d.field(d.label("Components with unclassified findings", "含未分級弱點的元件"), strconv.Itoa(review))
	}

	if urgent > 1 {
		d.field(d.label("Additional components to update immediately", "另有需立即更新的元件"), d.urgencyCount(urgent-1, evidenceComplete))
	}
	continuationLink := d.AddLink()
	label := d.label("View remediation order", "查看修補順序表")
	for _, line := range d.wrap(label, d.width) {
		d.ensureSpace(lineHeight)
		d.SetTextColor(20, 76, 88)
		d.Link(d.GetX(), d.GetY(), d.GetStringWidth(line.display), lineHeight, continuationLink)
		d.textCell(d.width, lineHeight, line, 1)
	}
	d.section(d.label("Priority action", "優先交辦項目"))
	d.remediationEntry(1, entries[0], levels, evidenceComplete)
	return continuationLink
}

func (d *document) remediationContinuation(entries []ssbom.ComponentAssessment, bom ssbom.FormattedSBOM, link int, evidenceComplete bool) {
	d.AddPage()
	d.SetLink(link, d.GetY(), d.PageNo())
	d.reportTable(d.label("Remediation order", "修補順序表"),
		d.remediationOrderNote(), []float64{13, d.width - 119, 21, 30, 28, 27},
		d.remediationHeaders(), d.remediationRows(entries, bom.ComponentInfo), 4)
	if len(entries) > 1 {
		d.section(d.label("Remediation priorities (continued)", "修補處理順序（續）"))
	}
	for i := 1; i < len(entries); i++ {
		d.remediationEntry(i+1, entries[i], bom.ComponentToLevel, evidenceComplete)
	}
}

func (d *document) remediationOrderNote() string {
	return d.label(
		"Max CVSS is the highest severity score for the component. The exploitation signal comes from the finding that determines its remediation order. Each finding uses the highest valid CVSS 2.0, 3.0, 3.1, or 4.0 score from its advisory. If the advisory has no usable score, check matching-package vectors, then use the scanner’s alias-group score if needed. Show the CVSS version when a vector matches the score.",
		"最高 CVSS 為該元件各筆弱點的最高分數。綜合利用指標取自決定順位的弱點。每筆弱點先從公告的 CVSS 2.0、3.0、3.1 與 4.0 向量中取有效最高分。公告缺少有效分數時，查找相符套件的向量，其次採用掃描器的別名群組分數。能對應到相符向量時才標示 CVSS 版本。",
	)
}

func (d *document) remediationHeaders() []string {
	return []string{
		d.label("Order", "順位"), d.label("Component and version", "元件與版本"), d.label("Max CVSS", "最高 CVSS"),
		d.label("Exploit signal", "綜合利用指標"), d.label("Action", "處理建議"), d.label("Test version", "建議驗測版本"),
	}
}

func (d *document) remediationRows(entries []ssbom.ComponentAssessment, components map[string]ssbom.Component) []reportTableRow {
	rows := make([]reportTableRow, 0, len(entries))
	for i, entry := range entries {
		cvss := d.label("Unscored", "未評分")
		highest := -1.0
		for _, finding := range components[entry.Key].Vulns {
			score, err := strconv.ParseFloat(finding.CVSSScore, 64)
			if err == nil && score > highest && score >= 0 && score <= 10 {
				highest, cvss = score, finding.CVSSScore
			}
		}
		version := entry.Upgrade
		if version == "" {
			version = d.label("Pending", "待確認")
		}
		rows = append(rows, reportTableRow{
			Cells: []string{strconv.Itoa(i + 1), strings.TrimSpace(entry.Name + " " + entry.Version), cvss,
				d.exploitationValue(entry.Driver.Signal), d.remediationPriorityLabel(entry.Driver.Priority), version},
			Urgent: entry.Driver.Priority == ssbom.RemediationUrgent,
		})
	}
	return rows
}

func (d *document) remediationPriorityLabel(priority ssbom.RemediationPriority) string {
	switch priority {
	case ssbom.RemediationUrgent:
		return d.label("Update immediately", "立即更新")
	case ssbom.RemediationElevated:
		return d.label("Prioritize fix assessment", "優先評估修補")
	case ssbom.RemediationAttention:
		return d.label("Schedule assessment", "安排評估")
	case ssbom.RemediationRoutine:
		return d.label("Routine maintenance", "例行維護")
	default:
		return d.label("Assess next", "待評估")
	}
}

func (d *document) remediationKEVList(ids []string, homepage bool) string {
	const homepageLimit = 4
	if !homepage || len(ids) <= homepageLimit {
		return strings.Join(ids, ", ")
	}
	return strings.Join(ids[:homepageLimit], ", ") + fmt.Sprintf(
		d.label(" · %d more in vulnerability details", "，另有 %d 筆見弱點明細"),
		len(ids)-homepageLimit,
	)
}

func (d *document) remediationEntry(rank int, entry ssbom.ComponentAssessment, levels map[string]int, evidenceComplete bool) {
	d.ensureSpace(3 * lineHeight)
	finding := entry.Driver.Finding
	homepage := rank == 1
	urgent := entry.Driver.Priority == ssbom.RemediationUrgent
	field := d.field
	cardPage, cardTop := d.PageNo(), d.GetY()
	if homepage {
		field = d.remediationCardField
		d.Ln(3)
	}
	label := d.remediationPriorityLabel(entry.Driver.Priority)
	switch entry.Driver.Priority {
	case ssbom.RemediationUrgent:
		d.SetTextColor(128, 26, 36)
	case ssbom.RemediationElevated:
		d.SetTextColor(117, 71, 0)
	}
	if homepage {
		d.SetFont(reportFont, "", 11)
	}
	title := strings.TrimSpace(entry.Name + " " + entry.Version)
	if homepage {
		const padding = 5.0
		for _, line := range d.wrap(fmt.Sprintf("%d. %s | %s", rank, label, title), d.width-2*padding) {
			d.ensureSpace(lineHeight)
			d.SetX(margin + padding)
			d.textCell(d.width-2*padding, lineHeight, line, 1)
		}
		d.Ln(2)
	} else {
		d.field(fmt.Sprintf("%d. %s", rank, label), title)
	}
	d.SetFont(reportFont, "", 9)
	d.SetTextColor(24, 37, 42)
	if entry.Package != "" {
		field(d.label("Package identity", "套件識別"), entry.Ecosystem+" · "+entry.Package)
	}
	score := finding.CVSSScore
	if !entry.Driver.HasCVSS {
		score = d.label("Unavailable", "未取得")
	}
	signal := d.exploitationValue(entry.Driver.Signal)
	if homepage && urgent {
		signal = d.label("Known exploitation (CISA KEV)", "已知遭利用（CISA KEV）")
	}
	field(d.label("Basis", "依據"), finding.ID+" · CVSS "+score+" · "+signal)
	if len(entry.KEVCVEs) > 0 {
		field(d.label("Listed by CISA KEV", "列入 CISA KEV"), d.remediationKEVList(entry.KEVCVEs, homepage))
	}
	if entry.Upgrade != "" {
		field(d.label("Upgrade to test", "建議驗測版本"), entry.Upgrade)
		var coveredKEV []string
		for _, id := range entry.UrgentCVEs {
			if !slices.Contains(entry.ResidualUrgentCVEs, id) {
				coveredKEV = append(coveredKEV, id)
			}
		}
		if len(coveredKEV) != 0 {
			field(d.label("KEV findings expected to be addressed", "預計涵蓋的 KEV 弱點"), d.remediationKEVList(coveredKEV, homepage))
		}
	} else if entry.KEVVersionPending {
		field(d.label("Upgrade to test", "建議驗測版本"), d.label("Pending", "待確認"))
	} else {
		field(d.label("Common fix version", "共同修補版本"),
			d.label("Unverified. See individual advisory candidates in the details.", "尚未驗證，個別公告候選請見弱點明細。"))
	}
	if len(entry.ResidualUrgentCVEs) > 0 {
		d.SetTextColor(128, 26, 36)
		label := d.label("KEV findings still to address", "仍待處理的 KEV 弱點")
		if entry.Upgrade != "" {
			label = d.label("KEV findings without confirmed coverage in this version", "此版本未確認涵蓋的 KEV 弱點")
		}
		field(label, d.remediationKEVList(entry.ResidualUrgentCVEs, homepage))
		d.SetTextColor(24, 37, 42)
	}
	action := d.label("Check advisory candidates and assess mitigations.", "查證公告候選版本，並評估緩解措施。")
	if entry.Upgrade != "" {
		action = d.label("Test the candidate, then confirm coverage with a new SBOM scan.", "驗測候選版本，再以新版 SBOM 複掃確認。")
	}
	if level, known := levels[entry.Key]; known && level > 0 {
		action = d.label("Identify the parent dependency and check its upgrade or lockfile. Confirm with a new SBOM scan.", "確認上游相依元件，檢查其升級方式或鎖定檔，再以新版 SBOM 複掃確認。")
	}
	if homepage && urgent {
		action = d.label("Confirm actual deployment and exposure. ", "確認實際部署與曝險。") + action
	}
	if entry.KEVVersionPending {
		action = d.confirmInstalledVersionAction()
		if !homepage {
			field(d.label("Fix coverage", "修補涵蓋範圍"), d.pendingRemediationCoverage())
		}
	}
	field(d.label("Next action", "下一步"), action)
	if homepage {
		if d.PageNo() == cardPage {
			height := d.GetY() - cardTop + 2
			d.SetDrawColor(186, 197, 203)
			if urgent {
				d.SetDrawColor(215, 177, 182)
			}
			d.Rect(margin, cardTop, d.width, height, "D")
			if urgent {
				d.SetFillColor(128, 26, 36)
				d.Rect(margin, cardTop, 1.2, height, "F")
			}
		}
		d.Ln(2)
		d.ensureSpace(4 + 6.5 + 5*lineHeight)
		d.section(d.label("If only action 1 is completed", "若本輪只完成第 1 項"))
		if entry.Upgrade == "" {
			d.write(d.pendingRemediationCoverage(), lineHeight)
		}
		d.SetFillColor(238, 242, 243)
		d.Rect(margin, d.GetY(), d.width, 3*lineHeight+4, "F")
		d.Ln(2)
		field = d.field
	}
	field(d.label("Cumulative findings expected to be addressed", "累計預計處理的元件弱點紀錄"), strconv.Itoa(entry.CumulativeCovered))
	field(d.label("CVEs expected to be addressed across all known affected components", "已知受影響元件均有方案的 CVE 數"), strconv.Itoa(entry.CumulativeFullyCoveredCVEs))
	field(d.label("Components still requiring immediate updates", "仍需立即更新的元件"), d.urgencyCount(entry.RemainingUrgent, evidenceComplete))
}

func (d *document) confirmInstalledVersionAction() string {
	return d.label(
		"Confirm the installed version and exposure manually before selecting a fix.",
		"請先人工確認已安裝版本與曝險情形，再選擇修補版本。",
	)
}

func (d *document) remediationPolicy() string {
	return fmt.Sprintf(d.label(
		"ex-sbom policy v%s. Update immediately for a matching CISA KEV entry with an identified installed version. Prioritize fix assessment for a KEV match with no installed version, or when a finding meets both thresholds (CVSS ≥ %.1f and exploitation signal ≥ %.0f%%). Schedule assessment when either threshold is met. Routine maintenance requires known CVSS and a complete signal below the thresholds. Other findings are marked Assess next and rank above routine maintenance, with higher CVSS first. When LEV was disabled at scan time, complete EPSS and KEV are sufficient.",
		"ex-sbom 排序規則 v%s。弱點列入 CISA KEV 且已識別安裝版本時，列為「立即更新」。KEV 命中但安裝版本不明，或同一弱點同時達到兩項門檻（CVSS ≥ %.1f 且綜合利用指標 ≥ %.0f%%），列為「優先評估修補」。僅達一項門檻時，列為「安排評估」。CVSS 已知、利用指標資料完整且兩項均低於門檻，列為「例行維護」。其餘列為「待評估」，排在例行維護之前，並優先處理 CVSS 較高者。掃描時未啟用 LEV，EPSS 與 KEV 資料齊全即可。"),
		ssbom.RemediationPolicyVersion, ssbom.CVSSThreshold, ssbom.RemediationThreshold*100)
}

func (d *document) repairVersionPolicy() string {
	return fmt.Sprintf(d.label(
		"For npm, Go and crates.io, select the lowest stable upgrade that addresses the advisories found in this scan for findings with CVSS ≥ %.1f or missing severity. When all findings score below %.1f, consider all findings in this scan. Keep the same major version, or the same minor series for 0.x. Check remaining findings and rescan after testing the upgrade.",
		"支援 npm、Go 與 crates.io。優先查核本次掃描中 CVSS ≥ %.1f 或缺少分數的弱點。若所有弱點都低於 %.1f，則查核本次掃描的全部弱點。依本次查到的公告選擇可涵蓋查核目標的最低穩定版本。升級限同一主要版本，0.x 限同一次要版本。請檢查其餘弱點，並於驗測後複掃。"),
		ssbom.CVSSThreshold, ssbom.CVSSThreshold)
}

func (d *document) exploitationMethod() string {
	return d.label(
		"Following NIST CSWP 41, the exploitation signal is max(EPSS, LEV, KEV) for each vulnerability. A CISA KEV match contributes 1. A successful check with no match contributes 0. Missing inputs are unknown. “At least” is a lower bound. If it reaches the signal threshold, the known data suffice for that threshold. If it falls below, verify missing inputs before deferring work. The signal ranks vulnerabilities. Actual exposure depends on the deployment. Confirm it with the operations team.",
		"參考 NIST CSWP 41，每筆弱點的綜合利用指標取 max(EPSS, LEV, KEV)。CISA KEV 命中取 1，查核成功且未列入取 0，缺項記為未知。「至少」表示已知下限。下限已達利用指標門檻時，即可判定此條件成立。下限低於門檻時，請先查證缺項，再決定是否延後。此指標用於排序，實際曝險請由維運單位依部署情形確認。")
}

func (d *document) exploitationValue(signal ssbom.ExploitationSignal) string {
	if !signal.Available {
		return d.label("Insufficient data", "資料不足")
	}
	percent := probabilityPercent(signal.Value)
	if !signal.Complete {
		percent = fmt.Sprintf(d.label("At least %s (incomplete data)", "至少 %s（資料未齊）"), percent)
	}
	if len(signal.Sources) > 0 {
		percent += " · " + strings.Join(signal.Sources, ", ")
	}
	return percent
}

func probabilityPercent(score float64) string {
	// Correct for scaling error without crossing the original score.
	hundredths := math.Floor(math.Nextafter(score*10000, math.Inf(1)))
	if hundredths/10000 > score {
		hundredths--
	}
	value := hundredths / 100
	return strings.TrimRight(strings.TrimRight(strconv.FormatFloat(value, 'f', 2, 64), "0"), ".") + "%"
}
