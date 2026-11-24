// SPDX-License-Identifier: MIT

package ssbom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"time"

	"ex-sbom/client/first"
)

const (
	historicalLEVBudget = 3 * time.Second
	maxReservationBytes = 32 << 20
)

func applyHistoricalLEV(ctx context.Context, bom *FormattedSBOM) {
	if bom.ReportSource == nil {
		return
	}
	dir := os.Getenv("EPSS_ARCHIVE_DIR")
	if dir == "" {
		bom.ReportSource.LEVArchiveStatus = LEVArchiveDisabled
		return
	}
	bom.ReportSource.LEVArchiveStatus = LEVArchiveConfigured
	if bom.ReportSource.QueriedAt == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, historicalLEVBudget)
	defer cancel()
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
	var reservations map[string]string
	if path := os.Getenv("CVE_RESERVATIONS_FILE"); path != "" {
		var err error
		reservations, err = readCVEReservations(ctx, path, cves)
		if err != nil {
			slog.Warn("Cannot read CVE reservation dates", "error", err)
		}
	}
	scores, err := first.ArchiveLEVContext(ctx, dir, first.FirstArchiveDay, asOf, cves, reservations)
	if err != nil {
		slog.Warn("EPSS archive has unusable data", "error", err)
	}
	setHistoricalLEV(bom, scores)
}

func readCVEReservations(ctx context.Context, path string, cves []string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxReservationBytes {
		return nil, fmt.Errorf("invalid CVE reservation file type or size")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	limited := &io.LimitedReader{R: file, N: maxReservationBytes + 1}
	decoder := json.NewDecoder(limited)
	if start, err := decoder.Token(); err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("invalid CVE reservation JSON object")
	}
	dates := make(map[string]string)
	badRows := 0
	for decoder.More() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		id := key.(string) // JSON object keys are strings.
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, err
		}
		if _, needed := slices.BinarySearch(cves, id); !needed {
			continue
		}
		var date string
		_, duplicate := dates[id]
		if err := json.Unmarshal(raw, &date); err != nil || date == "" || duplicate {
			badRows++
			date = ""
		}
		dates[id] = date
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, fmt.Errorf("invalid CVE reservation JSON object")
	}
	if err := decoder.Decode(new(any)); err != io.EOF || limited.N == 0 {
		return nil, fmt.Errorf("invalid trailing data or size for CVE reservations")
	}
	if badRows > 0 {
		return dates, fmt.Errorf("ignored %d invalid or duplicate CVE reservation entries", badRows)
	}
	return dates, nil
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
