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

func (v Vuln) listedCVEs() []string {
	if v.KEV != KEVListed {
		return nil
	}
	if len(v.KEVCVEs) > 0 {
		return v.KEVCVEs
	}
	if v.KEVCVE != "" {
		return []string{v.KEVCVE}
	}
	return nil
}
