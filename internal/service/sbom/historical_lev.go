// SPDX-License-Identifier: MIT

package ssbom

import (
	"log/slog"
	"os"
	"slices"
	"strconv"
	"time"

	"ex-sbom/client/first"
)

func applyHistoricalLEV(bom *FormattedSBOM) {
	dir := os.Getenv("EPSS_ARCHIVE_DIR")
	if dir == "" || bom.ReportSource == nil || bom.ReportSource.QueriedAt == nil {
		return
	}
	var cves []string
	for _, component := range bom.ComponentInfo {
		for _, finding := range component.Vulns {
			cves = append(cves, finding.CVEIDs...)
		}
	}
	if len(cves) == 0 {
		return
	}
	slices.Sort(cves)
	cves = slices.Compact(cves)
	// A UTC day that has ended is independent of the time an import runs.
	asOf := bom.ReportSource.QueriedAt.UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	scores, err := first.ArchiveLEV(dir, first.FirstArchiveDay, asOf, cves)
	if err != nil {
		slog.Warn("EPSS archive cannot establish historical LEV", "error", err)
		return
	}
	setHistoricalLEV(bom, scores)
}

func setHistoricalLEV(bom *FormattedSBOM, scores map[string]first.HistoricalLEV) {
	for _, component := range bom.ComponentInfo {
		for i := range component.Vulns {
			finding := &component.Vulns[i]
			best, available := scores[finding.ID]
			if !available {
				continue
			}
			finding.LEV = strconv.FormatFloat(best.Score, 'f', -1, 64)
			finding.LEVMethod = first.LEVMethod
			finding.LEVFirst = best.First
			finding.LEVAsOf = best.AsOf
			finding.LEVCVE = finding.ID
		}
	}
}
