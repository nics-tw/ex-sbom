// SPDX-License-Identifier: MIT

package ssbom

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"time"

	"ex-sbom/client/first"
)

const historicalLEVBudget = 3 * time.Second

// A blocked native call cannot keep the preview waiting or multiply workers.
var historicalLEVSlots = make(chan struct{}, 1)

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
	asOf := bom.ReportSource.QueriedAt.UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	reservations := os.Getenv("CVE_RESERVATIONS_FILE")
	if !acquireHistoricalLEV(ctx, historicalLEVSlots) {
		return
	}
	components, cves := copyHistoricalComponents(ctx, bom.ComponentInfo)
	if len(cves) == 0 {
		<-historicalLEVSlots
		return
	}
	result, ready := runHistoricalLEV(ctx, historicalLEVSlots, func() map[string]Component {
		slices.Sort(cves)
		scores := lookupHistoricalScores(ctx, dir, reservations, asOf, slices.Compact(cves), first.LookupArchiveIndex, first.ArchiveLEVContext)
		if len(scores) == 0 || ctx.Err() != nil {
			return nil
		}
		enriched := FormattedSBOM{ComponentInfo: components}
		setHistoricalLEV(&enriched, scores)
		return enriched.ComponentInfo
	})
	if ready && result != nil {
		bom.ComponentInfo = result
	}
}

func copyHistoricalComponents(ctx context.Context, source map[string]Component) (map[string]Component, []string) {
	components := make(map[string]Component, len(source))
	var cves []string
	for key, component := range source {
		if ctx.Err() != nil {
			return nil, nil
		}
		component.Vulns = slices.Clone(component.Vulns)
		for i := range component.Vulns {
			if ctx.Err() != nil {
				return nil, nil
			}
			finding := &component.Vulns[i]
			// Preview can sort its original findings and CVE IDs after timeout.
			finding.CVEIDs = slices.Clone(finding.CVEIDs)
			cves = append(cves, finding.CVEIDs...)
		}
		components[key] = component
	}
	return components, cves
}

func acquireHistoricalLEV(ctx context.Context, slots chan struct{}) bool {
	select {
	case <-ctx.Done():
		return false
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// The caller reserves a slot before copying input; the worker releases it.
func runHistoricalLEV[T any](ctx context.Context, slots chan struct{}, work func() T) (T, bool) {
	var zero T
	done := make(chan T, 1)
	go func() {
		var result T
		if ctx.Err() == nil {
			result = work()
		}
		<-slots
		done <- result
	}()
	select {
	case result := <-done:
		return result, ctx.Err() == nil
	case <-ctx.Done():
		return zero, false
	}
}

func lookupHistoricalScores(
	ctx context.Context,
	dir, reservationFile, asOf string,
	cves []string,
	lookup func(context.Context, string, string, string, []string) (map[string]first.HistoricalLEV, error),
	fallback func(context.Context, string, string, string, []string, map[string]string) (map[string]first.HistoricalLEV, error),
) map[string]first.HistoricalLEV {
	scores, err := lookup(ctx, dir, reservationFile, asOf, cves)
	if err == nil {
		return scores
	}
	if ctx.Err() != nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		slog.Warn("Cannot use EPSS archive index", "error", err)
	}

	// Leave part of the same budget for turning available raw observations
	// into a result and applying the alias aggregation.
	rawContext := ctx
	if deadline, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		rawContext, cancel = context.WithDeadline(ctx, deadline.Add(-50*time.Millisecond))
		defer cancel()
	}
	var reservations map[string]string
	if reservationFile != "" {
		reservations, err = first.ReadCVEReservations(rawContext, reservationFile, cves)
		if err != nil && rawContext.Err() == nil {
			slog.Warn("Cannot read CVE reservation dates", "error", err)
		}
	}
	scores, err = fallback(rawContext, dir, first.FirstArchiveDay, asOf, cves, reservations)
	if err != nil && rawContext.Err() == nil {
		slog.Warn("EPSS archive has unusable data", "error", err)
	}
	return scores
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
