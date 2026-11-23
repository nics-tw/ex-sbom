// SPDX-License-Identifier: MIT

package ssbom

import (
	"log/slog"
	"slices"
	"strings"
	"time"

	"ex-sbom/client/first"
	"ex-sbom/internal/service/lev"
)

func applyEPSS(components map[string]Component) {
	var cves []string
	for _, component := range components {
		for _, finding := range component.Vulns {
			if slices.Contains(finding.CVEIDs, finding.ID) {
				cves = append(cves, finding.ID)
			}
		}
	}
	if len(cves) == 0 {
		return
	}
	slices.Sort(cves)
	scores, err := lev.GetByChunk(slices.Compact(cves))
	if err != nil {
		slog.Warn("EPSS lookup failed", "error", err)
		return
	}
	for _, component := range components {
		for i := range component.Vulns {
			finding := &component.Vulns[i]
			data, found := scores[finding.ID]
			if !found {
				continue
			}
			if _, valid := first.ParseProbability(data.EPSS); valid {
				finding.EPSS = data.EPSS
			}
			if _, err := time.Parse(time.DateOnly, data.Date); err == nil {
				finding.EPSSDate = strings.TrimSpace(data.Date)
			}
		}
	}
}
