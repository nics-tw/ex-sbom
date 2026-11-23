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

func remediationEvidenceComplete(source *ssbom.ReportSource, components map[string]ssbom.Component) bool {
	if source.Status != ssbom.QueryCompleted {
		return false
	}
	for _, component := range components {
		for _, finding := range component.Vulns {
			if len(finding.CVEIDs) == 0 {
				// Older snapshots could record a CVE only as the displayed ID.
				if cisa.IsCVE(finding.ID) {
					return false
				}
				continue
			}
			if source.KEVCheckedAt == nil || (finding.KEV != ssbom.KEVListed && finding.KEV != ssbom.KEVUnlisted) {
				return false
			}
			if finding.KEV == ssbom.KEVListed && strings.TrimSpace(component.Version) == "" {
				return false
			}
		}
	}
	return true
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

func (d *document) remediationSummary(entries []ssbom.ComponentAssessment, levels map[string]int, source *ssbom.ReportSource, evidenceComplete bool) int {
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
	kevCVEs := make(map[string]struct{})
	for _, entry := range entries {
		if entry.Driver.Priority == ssbom.RemediationUrgent {
			urgent++
		}
		for _, id := range entry.UrgentCVEs {
			kevCVEs[id] = struct{}{}
		}
		if entry.NeedsReview > 0 {
			review++
		}
	}
	d.remediationMetrics(d.urgencyCount(urgent, evidenceComplete), d.urgencyCount(len(kevCVEs), evidenceComplete))
	if review != 0 {
		d.field(d.label("Components with findings to assess", "有待評估弱點的元件"), strconv.Itoa(review))
	}

	if urgent > 1 {
		d.field(d.label("Additional components to update immediately", "另有需立即更新的元件"), d.urgencyCount(urgent-1, evidenceComplete))
	}
	var continuationLink int
	if len(entries) > 1 {
		continuationLink = d.AddLink()
		label := d.label("See Remediation priorities (continued) for remaining components.", "其餘元件請見「修補處理順序（續）」。")
		for _, line := range d.wrap(label, d.width) {
			d.ensureSpace(lineHeight)
			d.SetTextColor(20, 76, 88)
			d.Link(d.GetX(), d.GetY(), d.GetStringWidth(line.display), lineHeight, continuationLink)
			d.textCell(d.width, lineHeight, line, 1)
		}
	}
	d.section(d.label("Priority action", "優先交辦項目"))
	d.remediationEntry(1, entries[0], levels, evidenceComplete)
	return continuationLink
}

func (d *document) remediationContinuation(entries []ssbom.ComponentAssessment, levels map[string]int, link int, evidenceComplete bool) {
	if link == 0 {
		return
	}
	d.AddPage()
	d.SetLink(link, d.GetY(), d.PageNo())
	d.section(d.label("Remediation priorities (continued)", "修補處理順序（續）"))
	for i := 1; i < len(entries); i++ {
		d.remediationEntry(i+1, entries[i], levels, evidenceComplete)
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
	label := d.label("Assess next", "待評估")
	switch entry.Driver.Priority {
	case ssbom.RemediationUrgent:
		label = d.label("Update immediately", "立即更新")
		d.SetTextColor(128, 26, 36)
	case ssbom.RemediationElevated:
		label = d.label("Prioritize fix assessment", "優先評估修補")
		d.SetTextColor(117, 71, 0)
	case ssbom.RemediationAttention:
		label = d.label("Schedule assessment", "安排評估")
	case ssbom.RemediationRoutine:
		label = d.label("Routine maintenance", "例行維護")
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
	if len(entry.UrgentCVEs) > 0 {
		field(d.label("Listed by CISA KEV", "列入 CISA KEV"), d.remediationKEVList(entry.UrgentCVEs, homepage))
	}
	if entry.Upgrade != "" {
		field(d.label("Upgrade to test", "建議驗測版本"), entry.Upgrade)
		if homepage {
			var coveredKEV []string
			for _, id := range entry.UrgentCVEs {
				if !slices.Contains(entry.ResidualUrgentCVEs, id) {
					coveredKEV = append(coveredKEV, id)
				}
			}
			if len(coveredKEV) != 0 {
				field(d.label("KEV findings expected to be addressed", "預計涵蓋的 KEV 弱點"), d.remediationKEVList(coveredKEV, homepage))
			}
		}
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

func (d *document) remediationPolicy() string {
	return fmt.Sprintf(d.label(
		"ex-sbom policy v%s. Update immediately when CISA KEV matches a vulnerability found for an identified component version. Prioritize fix assessment when CVSS ≥ %.1f and the exploitation signal ≥ %.0f%% for the same vulnerability.",
		"ex-sbom 排序規則 v%s。已識別元件版本，且其弱點列入 CISA KEV 時，列為「立即更新」。同一弱點的 CVSS ≥ %.1f 且綜合利用指標 ≥ %.0f%% 時，列為「優先評估修補」。"),
		ssbom.RemediationPolicyVersion, ssbom.CVSSThreshold, ssbom.RemediationThreshold*100)
}

func (d *document) repairVersionPolicy() string {
	return fmt.Sprintf(d.label(
		"Select the lowest stable upgrade verified against the advisories for all findings in this component with CVSS ≥ %.1f or missing severity. When all findings score below %.1f, consider all findings. Keep the same major version, or the same minor series for 0.x. Check remaining findings and rescan after testing the upgrade.",
		"優先查核元件內 CVSS ≥ %.1f 或嚴重性分數缺漏的弱點。若所有弱點都低於 %.1f，則查核全部弱點。依弱點公告選擇可涵蓋查核目標的最低穩定版本。升級限同一主要版本，0.x 限同一次要版本。請檢查其餘弱點，並於驗測後複掃。"),
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
