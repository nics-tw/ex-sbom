// SPDX-License-Identifier: MIT

package ssbom

import (
	"cmp"
	"slices"
	"strconv"
)

type RemediationPriority int

const (
	RemediationRoutine RemediationPriority = iota
	RemediationReview
	RemediationAttention
	RemediationElevated
	RemediationUrgent
)

const (
	RemediationPolicyVersion = "3"
	RemediationThreshold     = 0.10
)

type FindingAssessment struct {
	index    int
	kevCVEs  []string
	Finding  Vuln
	Signal   ExploitationSignal
	CVSS     float64
	HasCVSS  bool
	KEVMatch bool
	Priority RemediationPriority
}

type ComponentAssessment struct {
	KEVCVEs                    []string
	KEVVersionPending          bool
	Key                        string
	Name                       string
	Version                    string
	Driver                     FindingAssessment
	NeedsReview                int
	UrgentCVEs                 []string
	Upgrade                    string
	CoveredFindings            []bool
	Covered                    int
	coveredPriority            int
	Package                    string
	Ecosystem                  string
	CumulativeCovered          int
	CumulativeFullyCoveredCVEs int
	coveredCVEs                []string
	RemainingUrgent            int
	ResidualUrgentCVEs         []string
	resolvedUrgent             bool
}

// RemediationAssessments ranks each stored component/version by its highest
// priority finding. A nil threshold leaves policy-based levels unassigned.
func (bom FormattedSBOM) RemediationAssessments(threshold *float64) []ComponentAssessment {
	var result []ComponentAssessment
	remainingByCVE := make(map[string]int)
	displayCounts := make(map[[2]string]int)
	for _, component := range bom.ComponentInfo {
		displayCounts[[2]string{component.Name, component.Version}]++
	}
	for key, component := range bom.ComponentInfo {
		if len(component.Vulns) == 0 {
			continue
		}
		entry := ComponentAssessment{Key: key, Name: component.Name, Version: component.Version}
		if displayCounts[[2]string{component.Name, component.Version}] > 1 && key != "" {
			entry.Name += " (" + key + ")"
		}
		findings := make([]FindingAssessment, 0, len(component.Vulns))
		confirmedVersion := component.ConfirmedInstalledVersion()
		for i, finding := range component.Vulns {
			item := assessFinding(finding, confirmedVersion, threshold, bom.ReportSource)
			item.index = i
			findings = append(findings, item)
			entry.KEVCVEs = append(entry.KEVCVEs, item.kevCVEs...)
			for _, cve := range finding.CVEIDs {
				remainingByCVE[cve]++
			}
			if i == 0 || compareFindings(item, entry.Driver) < 0 {
				entry.Driver = item
			}
			if item.Priority == RemediationReview {
				entry.NeedsReview++
			}
		}
		slices.Sort(entry.KEVCVEs)
		entry.KEVCVEs = slices.Compact(entry.KEVCVEs)
		entry.KEVVersionPending = len(entry.KEVCVEs) != 0 && confirmedVersion == ""
		if !entry.KEVVersionPending {
			entry.UrgentCVEs = entry.KEVCVEs
		}

		repairVersion := confirmedVersion
		if component.InstalledVersion == nil && !entry.KEVVersionPending {
			repairVersion = component.Version
		}
		upgrade, covered := verifiedRepair(repairVersion, findings)
		entry.Upgrade = upgrade
		if evidence := entry.Driver.Finding.RepairEvidence; evidence != nil {
			entry.Package, entry.Ecosystem = evidence.Package, evidence.Ecosystem
		}
		entry.Covered = len(covered)
		entry.CoveredFindings = make([]bool, len(findings))
		for _, item := range covered {
			entry.CoveredFindings[item.index] = true
			entry.coveredCVEs = append(entry.coveredCVEs, item.Finding.CVEIDs...)
			if item.Priority >= RemediationElevated || (item.HasCVSS && item.CVSS >= CVSSThreshold) {
				entry.coveredPriority++
			}
		}
		entry.ResidualUrgentCVEs = append([]string(nil), entry.UrgentCVEs...)
		if entry.Upgrade != "" {
			for _, id := range entry.UrgentCVEs {
				total, resolved := 0, 0
				for _, item := range findings {
					if slices.Contains(item.kevCVEs, id) {
						total++
					}
				}
				for _, item := range covered {
					if slices.Contains(item.kevCVEs, id) {
						resolved++
					}
				}
				if total == resolved {
					entry.ResidualUrgentCVEs = slices.DeleteFunc(entry.ResidualUrgentCVEs, func(remaining string) bool { return remaining == id })
				}
			}
		}
		entry.resolvedUrgent = len(entry.UrgentCVEs) > 0 && len(entry.ResidualUrgentCVEs) == 0
		result = append(result, entry)
	}
	slices.SortFunc(result, func(a, b ComponentAssessment) int {
		return cmp.Or(compareAssessment(a.Driver, b.Driver), cmp.Compare(b.coveredPriority, a.coveredPriority), cmp.Compare(a.Key, b.Key))
	})
	remainingUrgent, cumulative, fullyCovered := 0, 0, 0
	for _, entry := range result {
		if len(entry.UrgentCVEs) > 0 {
			remainingUrgent++
		}
	}
	for i := range result {
		entry := &result[i]
		cumulative += entry.Covered
		if entry.resolvedUrgent {
			remainingUrgent--
		}
		entry.CumulativeCovered = cumulative
		for _, cve := range entry.coveredCVEs {
			remainingByCVE[cve]--
			if remainingByCVE[cve] == 0 {
				fullyCovered++
			}
		}
		entry.CumulativeFullyCoveredCVEs = fullyCovered
		entry.RemainingUrgent = remainingUrgent
	}
	return result
}

func assessFinding(finding Vuln, confirmedVersion string, threshold *float64, source *ReportSource) FindingAssessment {
	score, err := strconv.ParseFloat(finding.CVSSScore, 64)
	kev, cves := finding.KEVEvidence()
	kevMatch := len(cves) != 0
	signal := finding.ExploitationSignal(kev, source)
	item := FindingAssessment{
		Finding: finding, Signal: signal, CVSS: score, HasCVSS: err == nil && score >= 0 && score <= 10,
		KEVMatch: kevMatch, kevCVEs: cves, Priority: RemediationReview,
	}
	highCVSS := item.HasCVSS && score >= CVSSThreshold
	highSignal := threshold != nil && signal.Available && signal.Value >= *threshold
	switch {
	case kevMatch && confirmedVersion != "":
		item.Priority = RemediationUrgent
	case kevMatch || highCVSS && highSignal:
		item.Priority = RemediationElevated
	case threshold != nil && (highCVSS || highSignal):
		item.Priority = RemediationAttention
	case threshold != nil && item.HasCVSS && signal.Complete:
		item.Priority = RemediationRoutine
	}
	return item
}

func compareFindings(a, b FindingAssessment) int {
	return cmp.Or(compareAssessment(a, b), compareVulns(a.Finding, b.Finding))
}

func compareAssessment(a, b FindingAssessment) int {
	severity := 0
	if a.HasCVSS && b.HasCVSS {
		severity = cmp.Compare(b.CVSS, a.CVSS)
	} else if a.HasCVSS {
		severity = -1
	} else if b.HasCVSS {
		severity = 1
	}
	if a.Priority == RemediationReview && b.Priority == RemediationReview && severity != 0 {
		return severity
	}
	return cmp.Or(cmp.Compare(b.Priority, a.Priority), compareKnown(a.KEVMatch, b.KEVMatch),
		compareKnown(a.Signal.Available, b.Signal.Available), cmp.Compare(b.Signal.Value, a.Signal.Value),
		compareKnown(a.Signal.Complete, b.Signal.Complete), severity)
}

func compareKnown(a, b bool) int {
	if a == b {
		return 0
	}
	if a {
		return -1
	}
	return 1
}
