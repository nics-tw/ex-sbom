// SPDX-License-Identifier: MIT

package ssbom

import (
	"encoding/json"
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
	reservations := make(map[string]string)
	if path := os.Getenv("CVE_RESERVATIONS_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("Cannot read CVE reservation dates", "error", err)
		} else if err := json.Unmarshal(data, &reservations); err != nil {
			clear(reservations)
			slog.Warn("Cannot decode CVE reservation dates", "error", err)
		}
	}
	scores, err := first.ArchiveLEVWithReservations(dir, first.FirstArchiveDay, asOf, cves, reservations)
	if err != nil {
		slog.Warn("EPSS archive has unusable data", "error", err)
	}
	setHistoricalLEV(bom, scores)
}

func setHistoricalLEV(bom *FormattedSBOM, scores map[string]first.HistoricalLEV) {
	for _, component := range bom.ComponentInfo {
		for i := range component.Vulns {
			finding := &component.Vulns[i]
			var best first.HistoricalLEV
			var bestID string
			partial := false
			for _, id := range finding.CVEIDs {
				score, available := scores[id]
				partial = partial || !available || score.Partial
				if !available || (bestID != "" && (score.Score < best.Score ||
					(score.Score == best.Score && id >= bestID))) {
					continue
				}
				best, bestID = score, id
			}
			if bestID == "" {
				continue
			}
			finding.LEV = strconv.FormatFloat(best.Score, 'f', -1, 64)
			finding.LEVMethod = first.LEVMethod
			finding.LEVFirst = best.First
			finding.LEVAsOf = best.AsOf
			finding.LEVPartial = partial
			finding.LEVCVE = bestID
		}
	}
}
