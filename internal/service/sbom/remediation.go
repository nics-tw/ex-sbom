// SPDX-License-Identifier: MIT

package ssbom

import (
	"cmp"
	"slices"
	"strconv"
)

type RemediationPriority int

const (
	RemediationReview RemediationPriority = iota
	RemediationRoutine
	RemediationElevated
	RemediationUrgent
)

type FindingAssessment struct {
	Finding  Vuln
	Signal   ExploitationSignal
	CVSS     float64
	HasCVSS  bool
	Priority RemediationPriority
}

type ComponentAssessment struct {
	Key         string
	Name        string
	Version     string
	Driver      FindingAssessment
	NeedsReview int
	UrgentCVEs  []string
}

// RemediationAssessments ranks each stored component/version by its highest
// priority finding. A nil threshold leaves policy-based levels unassigned.
func (bom FormattedSBOM) RemediationAssessments(threshold *float64) []ComponentAssessment {
	var result []ComponentAssessment
	for key, component := range bom.ComponentInfo {
		if len(component.Vulns) == 0 {
			continue
		}
		entry := ComponentAssessment{Key: key, Name: component.Name, Version: component.Version}
		for i, finding := range component.Vulns {
			item := assessFinding(finding, component.Version, threshold)
			if i == 0 || compareFindings(item, entry.Driver) < 0 {
				entry.Driver = item
			}
			switch item.Priority {
			case RemediationReview:
				entry.NeedsReview++
			case RemediationUrgent:
				entry.UrgentCVEs = append(entry.UrgentCVEs, finding.KEVCVE)
			}
		}
		slices.Sort(entry.UrgentCVEs)
		entry.UrgentCVEs = slices.Compact(entry.UrgentCVEs)
		result = append(result, entry)
	}
	slices.SortFunc(result, func(a, b ComponentAssessment) int {
		return cmp.Or(compareAssessment(a.Driver, b.Driver), cmp.Compare(a.Key, b.Key))
	})
	return result
}

func assessFinding(finding Vuln, version string, threshold *float64) FindingAssessment {
	score, err := strconv.ParseFloat(finding.CVSSScore, 64)
	signal := finding.ExploitationSignal(finding.KEV)
	item := FindingAssessment{Finding: finding, Signal: signal, CVSS: score, HasCVSS: err == nil && score >= 0 && score <= 10}
	// The catalog match is saved only for scanner findings keyed to this
	// component and version. A finding without an installed version needs review.
	if version != "" && finding.KEV == KEVListed && slices.Contains(finding.CVEIDs, finding.KEVCVE) && finding.KEVCVE != "" {
		item.Priority = RemediationUrgent
	} else if threshold != nil && item.HasCVSS && signal.Available {
		switch {
		case signal.Value >= *threshold || (signal.Complete && item.CVSS >= CVSSThreshold):
			item.Priority = RemediationElevated
		case signal.Complete:
			item.Priority = RemediationRoutine
		}
	}
	return item
}

func compareFindings(a, b FindingAssessment) int {
	return cmp.Or(compareAssessment(a, b), cmp.Compare(a.Finding.ID, b.Finding.ID),
		cmp.Compare(a.Finding.KEVCVE, b.Finding.KEVCVE))
}

func compareAssessment(a, b FindingAssessment) int {
	if a.Signal.Available != b.Signal.Available && a.Priority == b.Priority {
		if a.Signal.Available {
			return -1
		}
		return 1
	}
	certainty := 0
	if a.Signal.Complete != b.Signal.Complete {
		certainty = 1
		if a.Signal.Complete {
			certainty = -1
		}
	}
	severity := 0
	if a.HasCVSS && b.HasCVSS {
		severity = cmp.Compare(b.CVSS, a.CVSS)
	} else if a.HasCVSS {
		severity = -1
	} else if b.HasCVSS {
		severity = 1
	}
	return cmp.Or(cmp.Compare(b.Priority, a.Priority), cmp.Compare(b.Signal.Value, a.Signal.Value), certainty, severity)
}
