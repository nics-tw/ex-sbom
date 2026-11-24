// SPDX-License-Identifier: MIT

package ssbom

import (
	"slices"

	"ex-sbom/client/cisa"
)

func findingCVEs(id string, aliases []string) []string {
	var cves []string
	if cisa.IsCVE(id) {
		cves = append(cves, id)
	}
	for _, alias := range aliases {
		if cisa.IsCVE(alias) {
			cves = append(cves, alias)
		}
	}
	slices.Sort(cves)
	return slices.Compact(cves)
}

func applyKEV(bom *FormattedSBOM, current func() (cisa.Catalog, error)) {
	if bom.ReportSource == nil {
		return
	}
	var catalog cisa.Catalog
	loaded := false
	for _, component := range bom.ComponentInfo {
		for i := range component.Vulns {
			finding := &component.Vulns[i]
			if len(finding.CVEIDs) == 0 {
				continue
			}
			if !loaded {
				var err error
				catalog, err = current()
				if err != nil {
					return
				}
				loaded = true
				checkedAt := catalog.RetrievedAt
				bom.ReportSource.KEVCheckedAt = &checkedAt
				bom.ReportSource.KEVCatalogVersion = catalog.Version
			}
			finding.KEV = KEVUnlisted
			for _, id := range finding.CVEIDs {
				if catalog.Contains(id) {
					finding.KEV = KEVListed
					finding.KEVCVEs = append(finding.KEVCVEs, id)
				}
			}
		}
	}
}

// KEVEvidence returns the recorded status and the listed CVEs that match this finding.
func (v Vuln) KEVEvidence() (KEVStatus, []string) {
	if v.KEV != KEVListed {
		return v.KEV, nil
	}
	ids := v.KEVCVEs
	if len(ids) == 0 && v.KEVCVE != "" {
		ids = []string{v.KEVCVE}
	}
	var matched []string
	for _, id := range ids {
		if slices.Contains(v.CVEIDs, id) {
			matched = append(matched, id)
		}
	}
	if len(matched) == 0 {
		return KEVUnknown, nil
	}
	return KEVListed, matched
}
