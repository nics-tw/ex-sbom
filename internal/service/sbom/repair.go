// SPDX-License-Identifier: MIT

package ssbom

import (
	"cmp"
	"slices"
	"strings"

	"ex-sbom/util/file"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/mod/semver"
)

// RepairEvidence retains the advisory ranges for the exact scanned package.
type RepairEvidence struct {
	AdvisoryID string           `json:"advisory_id"`
	Ecosystem  string           `json:"ecosystem"`
	Package    string           `json:"package"`
	Installed  string           `json:"installed"`
	Ranges     []RepairInterval `json:"ranges"`
	Versions   []string         `json:"versions,omitempty"`
}

type RepairInterval struct {
	Start string `json:"introduced"`
	Fixed string `json:"fixed,omitempty"`
	Last  string `json:"last_affected,omitempty"`
}

func matchedRepairEvidence(advisory *osvschema.Vulnerability, identity file.PackageVersion) *RepairEvidence {
	switch identity.Ecosystem {
	case "npm", "Go", "crates.io":
	default:
		return nil
	}
	e := &RepairEvidence{AdvisoryID: advisory.GetId(), Ecosystem: identity.Ecosystem, Package: identity.Name, Installed: identity.Version}
	for _, affected := range advisory.GetAffected() {
		pkg := affected.GetPackage()
		if pkg.GetEcosystem() != identity.Ecosystem || pkg.GetName() != identity.Name {
			continue
		}
		for _, version := range affected.GetVersions() {
			if !semver.IsValid(repairVersion(version)) {
				return nil
			}
			e.Versions = append(e.Versions, version)
		}
		for _, r := range affected.GetRanges() {
			// A limit does not establish a repair version. Unknown range
			// types also prevent a verified coverage claim.
			if r.GetType() != osvschema.Range_SEMVER && r.GetType() != osvschema.Range_ECOSYSTEM {
				return nil
			}
			intervals, valid := repairIntervals(r.GetEvents())
			if !valid {
				return nil
			}
			e.Ranges = append(e.Ranges, intervals...)
		}
	}
	slices.SortFunc(e.Ranges, compareRepairIntervals)
	e.Ranges = slices.Compact(e.Ranges)
	slices.Sort(e.Versions)
	e.Versions = slices.Compact(e.Versions)
	if len(e.Ranges) == 0 || !semver.IsValid(repairVersion(e.Installed)) || !e.affects(e.Installed) {
		return nil
	}
	return e
}

func repairVersion(value string) string {
	if strings.HasPrefix(value, "v") {
		return value
	}
	return "v" + value
}

// IsGoComponent checks the recorded identity, with matching repair evidence
// as a fallback for snapshots saved before the component identity was kept.
func IsGoComponent(source *ReportSource, key string, component Component) bool {
	if source != nil && source.GoComponents[key] {
		return true
	}
	for _, finding := range component.Vulns {
		evidence := finding.RepairEvidence
		if evidence != nil && evidence.Ecosystem == "Go" && evidence.Package == component.Name &&
			component.Version != "" && repairVersion(evidence.Installed) == repairVersion(component.Version) {
			return true
		}
	}
	return false
}

// GoCandidateVersions formats advisory versions for display, preserving
// values the Go version parser cannot verify and the order of candidates.
func GoCandidateVersions(versions string) string {
	if versions == "" {
		return ""
	}
	parts := strings.Split(versions, ", ")
	for i, version := range parts {
		candidate := repairVersion(version)
		if semver.IsValid(candidate) {
			parts[i] = candidate
		}
	}
	return getVersionString(parts)
}

// GoAdvisoryDisplay formats a finding's advisory candidates for a confirmed Go component.
func (v Vuln) GoAdvisoryDisplay() Vuln {
	v.SuggestFixVersion = GoCandidateVersions(v.SuggestFixVersion)
	v.OtherFixVersions = GoCandidateVersions(v.OtherFixVersions)
	return v
}

func repairIntervals(events []*osvschema.Event) ([]RepairInterval, bool) {
	var intervals []RepairInterval
	var interval RepairInterval
	for _, event := range events {
		start, fixed, last := event.GetIntroduced(), event.GetFixed(), event.GetLastAffected()
		switch {
		case start != "" && interval.Start == "" && (start == "0" || semver.IsValid(repairVersion(start))):
			interval.Start = start
		case interval.Start != "" && (fixed != "" || last != ""):
			end := cmp.Or(fixed, last)
			if !semver.IsValid(repairVersion(end)) || (interval.Start != "0" && semver.Compare(repairVersion(interval.Start), repairVersion(end)) > 0) {
				return nil, false
			}
			interval.Fixed, interval.Last = fixed, last
			intervals = append(intervals, interval)
			interval = RepairInterval{}
		default:
			return nil, false
		}
	}
	if interval.Start != "" {
		intervals = append(intervals, interval)
	}
	return intervals, len(intervals) > 0
}

func (e RepairEvidence) affects(value string) bool {
	version := repairVersion(value)
	for _, explicitlyAffected := range e.Versions {
		if !semver.IsValid(repairVersion(explicitlyAffected)) || semver.Compare(version, repairVersion(explicitlyAffected)) == 0 {
			return true
		}
	}
	for _, r := range e.Ranges {
		if r.Start != "0" && semver.Compare(version, repairVersion(r.Start)) < 0 {
			continue
		}
		if r.Fixed != "" && semver.Compare(version, repairVersion(r.Fixed)) >= 0 {
			continue
		}
		if r.Last != "" && semver.Compare(version, repairVersion(r.Last)) > 0 {
			continue
		}
		return true
	}
	return false
}

func verifiedRepair(findings []FindingAssessment) (string, []FindingAssessment) {
	if len(findings) == 0 {
		return "", nil
	}
	var targets []FindingAssessment
	for _, item := range findings {
		if !item.HasCVSS || item.CVSS >= CVSSThreshold {
			targets = append(targets, item)
		}
	}
	if len(targets) == 0 {
		targets = findings
	}
	var candidates []string
	identity := targets[0].Finding.RepairEvidence
	if identity == nil {
		return "", nil
	}
	for _, item := range targets {
		e := item.Finding.RepairEvidence
		if e == nil || e.Ecosystem != identity.Ecosystem || e.Package != identity.Package || e.Installed != identity.Installed {
			return "", nil
		}
		for _, r := range e.Ranges {
			candidate := repairVersion(r.Fixed)
			current := repairVersion(e.Installed)
			if semver.IsValid(candidate) && semver.Prerelease(candidate) == "" &&
				compatibleRepairSeries(candidate, current) && semver.Compare(candidate, current) > 0 {
				candidates = append(candidates, r.Fixed)
			}
		}
	}
	slices.SortFunc(candidates, func(a, b string) int {
		return cmp.Or(semver.Compare(repairVersion(a), repairVersion(b)), cmp.Compare(a, b))
	})
	for _, candidate := range slices.Compact(candidates) {
		if slices.ContainsFunc(targets, func(item FindingAssessment) bool {
			return item.Finding.RepairEvidence.affects(candidate)
		}) {
			continue
		}
		var covered []FindingAssessment
		for _, item := range findings {
			e := item.Finding.RepairEvidence
			if e != nil && e.Ecosystem == identity.Ecosystem && e.Package == identity.Package &&
				e.Installed == identity.Installed && !e.affects(candidate) {
				covered = append(covered, item)
			}
		}
		if identity.Ecosystem == "Go" {
			candidate = repairVersion(candidate)
		}
		return candidate, covered
	}
	return "", nil
}

func compatibleRepairSeries(candidate, current string) bool {
	major := semver.Major(current)
	if major != semver.Major(candidate) {
		return false
	}
	return major != "v0" || semver.MajorMinor(candidate) == semver.MajorMinor(current)
}

func compareRepairIntervals(a, b RepairInterval) int {
	return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(a.Fixed, b.Fixed), cmp.Compare(a.Last, b.Last))
}

func compareRepairEvidence(a, b *RepairEvidence) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	return cmp.Or(cmp.Compare(a.AdvisoryID, b.AdvisoryID), cmp.Compare(a.Ecosystem, b.Ecosystem),
		cmp.Compare(a.Package, b.Package), cmp.Compare(a.Installed, b.Installed),
		slices.Compare(a.Versions, b.Versions), slices.CompareFunc(a.Ranges, b.Ranges, compareRepairIntervals))
}
