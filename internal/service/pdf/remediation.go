// SPDX-License-Identifier: MIT

package pdf

import (
	"fmt"
	"strconv"
	"strings"

	ssbom "ex-sbom/internal/service/sbom"
)

const remediationPreviewLimit = 3

func (d *document) remediationSummary(entries []ssbom.ComponentAssessment) {
	if len(entries) == 0 {
		return
	}
	d.section(d.label("Remediation priorities", "修補處理順序"))
	urgent, review := 0, 0
	for _, entry := range entries {
		if entry.Driver.Priority == ssbom.RemediationUrgent {
			urgent++
		}
		if entry.NeedsReview > 0 {
			review++
		}
	}
	d.field(d.label("Components to verify immediately", "需立即查證的元件"), strconv.Itoa(urgent))
	d.field(d.label("Components with findings to assess", "有待評估弱點的元件"), strconv.Itoa(review))
	d.write(d.label(
		"Confirm deployment and exposure with the system owner. Other entries are ordered by available evidence while priority thresholds are being calibrated.",
		"請維運單位確認實際部署與曝險。其餘項目先依已知證據排列，分級門檻待校準。"), lineHeight)

	for i, entry := range entries[:min(len(entries), remediationPreviewLimit)] {
		d.remediationEntry(i+1, entry)
	}
	if urgent > remediationPreviewLimit {
		d.field(d.label("Additional urgent components", "另有立即查證元件"), strconv.Itoa(urgent-remediationPreviewLimit))
	}
	if len(entries) > remediationPreviewLimit {
		d.write(d.label("See Remediation priorities (continued) for remaining components.", "其餘元件請見「修補處理順序（續）」。"), lineHeight)
	}
}

func (d *document) remediationContinuation(entries []ssbom.ComponentAssessment) {
	if len(entries) <= remediationPreviewLimit {
		return
	}
	d.section(d.label("Remediation priorities (continued)", "修補處理順序（續）"))
	for i := remediationPreviewLimit; i < len(entries); i++ {
		d.remediationEntry(i+1, entries[i])
	}
}

func (d *document) remediationEntry(rank int, entry ssbom.ComponentAssessment) {
	d.ensureSpace(3 * lineHeight)
	finding := entry.Driver.Finding
	label := d.label("Assess next", "待評估")
	switch entry.Driver.Priority {
	case ssbom.RemediationUrgent:
		label = d.label("Verify immediately", "立即查證")
		d.SetTextColor(128, 26, 36)
	case ssbom.RemediationElevated:
		label = d.label("Prioritize fix assessment", "優先評估修補")
		d.SetTextColor(117, 71, 0)
	case ssbom.RemediationRoutine:
		label = d.label("Routine maintenance", "例行維護")
	}
	d.field(fmt.Sprintf("%d. %s", rank, label), strings.TrimSpace(entry.Name+" "+entry.Version))
	d.SetTextColor(24, 37, 42)
	score := finding.CVSSScore
	if !entry.Driver.HasCVSS {
		score = d.label("Unavailable", "未取得")
	}
	d.field(d.label("Basis", "依據"), finding.ID+" · CVSS "+score+" · "+d.exploitationValue(entry.Driver.Signal))
	if len(entry.UrgentCVEs) > 0 {
		d.field(d.label("Listed by CISA KEV", "列入 CISA KEV"), strings.Join(entry.UrgentCVEs, ", "))
	}
	upgrade := entry.Upgrade
	if upgrade == "" {
		upgrade = d.label("Verify candidate or mitigation", "查證候選版本或評估緩解措施")
	}
	d.field(d.label("Upgrade to test", "建議驗測版本"), upgrade)
	d.field(d.label("Cumulative findings expected to be addressed", "累計預計處理的元件弱點紀錄"), strconv.Itoa(entry.CumulativeCovered))
	d.field(d.label("CVEs covered across all known affected components", "已知受影響元件均有方案的 CVE 數"), strconv.Itoa(entry.CumulativeFullyCoveredCVEs))
	d.field(d.label("Urgent components still to address", "仍待處理的立即查證元件"), strconv.Itoa(entry.RemainingUrgent))
	if len(entry.ResidualUrgentCVEs) > 0 {
		d.SetTextColor(128, 26, 36)
		d.field(d.label("KEV findings still to address", "仍待處理的 KEV 弱點"), strings.Join(entry.ResidualUrgentCVEs, ", "))
		d.SetTextColor(24, 37, 42)
	}
}

func (d *document) exploitationValue(signal ssbom.ExploitationSignal) string {
	if !signal.Available {
		return d.label("Insufficient data", "資料不足")
	}
	percent := strconv.FormatFloat(signal.Value*100, 'f', -1, 64) + "%"
	if !signal.Complete {
		percent = fmt.Sprintf(d.label("At least %s (incomplete data)", "至少 %s（資料未齊）"), percent)
	}
	if len(signal.Sources) > 0 {
		percent += " · " + strings.Join(signal.Sources, ", ")
	}
	return percent
}
