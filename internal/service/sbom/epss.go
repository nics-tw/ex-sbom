// SPDX-License-Identifier: MIT

package ssbom

import (
	"log/slog"
	"slices"
	"time"

	"ex-sbom/client/first"
	"ex-sbom/internal/service/lev"
)

func applyEPSS(components map[string]Component) {
	var cves []string
	for _, component := range components {
		for _, finding := range component.Vulns {
			cves = append(cves, finding.CVEIDs...)
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
	setEPSS(components, scores)
}

func setEPSS(components map[string]Component, scores map[string]first.EPSS) {
	for _, component := range components {
		for i := range component.Vulns {
			finding := &component.Vulns[i]
			maximum := -1.0
			for _, id := range finding.CVEIDs {
				data := scores[id]
				score, valid := first.ParseProbability(data.EPSS)
				if !valid {
					finding.EPSSPartial = true
					continue
				}
				if score < maximum || (score == maximum && id >= finding.EPSSCVE) {
					continue
				}
				maximum = score
				finding.EPSS = data.EPSS
				finding.EPSSCVE = id
				finding.EPSSDate = ""
				if _, err := time.Parse(time.DateOnly, data.Date); err == nil {
					finding.EPSSDate = data.Date
				}
			}
		}
	}
}
