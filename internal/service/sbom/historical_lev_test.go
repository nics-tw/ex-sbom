//go:build unit

// SPDX-License-Identifier: MIT

package ssbom

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"ex-sbom/client/first"

	"github.com/stretchr/testify/require"
)

func TestHistoricalLEVStopsWaitingForBlockedWork(t *testing.T) {
	slot := make(chan struct{}, 1)
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	t.Cleanup(func() {
		close(release)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("blocked worker did not clean up")
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	require.True(t, acquireHistoricalLEV(ctx, slot))
	go func() {
		<-started
		cancel()
	}()
	type result struct{ value string }
	value, ok := runHistoricalLEV(ctx, slot, func() result {
		defer close(done)
		close(started)
		<-release
		return result{value: "late"}
	})
	require.False(t, ok)
	require.Empty(t, value.value)
	require.False(t, acquireHistoricalLEV(context.Background(), slot))
}

func TestHistoricalLEVPrefersCompleteIndexOrUsesSameDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	const id = "CVE-2026-0001"
	want := map[string]first.HistoricalLEV{id: {Score: 0.25, First: "2026-11-23", AsOf: "2026-11-23", Partial: true}}
	failedIndex := func(context.Context, string, string, string, []string) (map[string]first.HistoricalLEV, error) {
		return map[string]first.HistoricalLEV{id: {Score: 1}}, os.ErrInvalid
	}
	fallback := func(got context.Context, dir, firstDay, asOf string, cves []string, reserved map[string]string) (map[string]first.HistoricalLEV, error) {
		parentDeadline, _ := ctx.Deadline()
		gotDeadline, hasDeadline := got.Deadline()
		require.True(t, hasDeadline)
		require.True(t, gotDeadline.Before(parentDeadline))
		require.Equal(t, first.FirstArchiveDay, firstDay)
		require.Equal(t, "2026-11-23", asOf)
		return want, nil
	}
	got := lookupHistoricalScores(ctx, t.TempDir(), "", "2026-11-23", []string{id}, failedIndex, fallback)
	require.Equal(t, want, got)
}

func TestApplyHistoricalLEVUsesIndependentReservationDates(t *testing.T) {
	const id, other, day = "CVE-2026-0001", "CVE-2026-0002", "2026-11-23"
	dir := t.TempDir()
	reservations := filepath.Join(dir, "reservations.json")
	require.NoError(t, os.WriteFile(reservations, []byte(`{"CVE-2026-0001":"2026-11-23","CVE-2026-0002":42}`), 0600))
	file, err := os.Create(filepath.Join(dir, "epss_scores-"+day+".csv.gz"))
	require.NoError(t, err)
	stream := gzip.NewWriter(file)
	_, err = stream.Write([]byte("cve,epss\n" + id + ",0.6\n" + other + ",0.9\n"))
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	require.NoError(t, file.Close())
	queriedAt := time.Date(2026, time.November, 24, 0, 0, 0, 0, time.UTC)
	bom := FormattedSBOM{
		ReportSource: &ReportSource{QueriedAt: &queriedAt},
		ComponentInfo: map[string]Component{"test": {Vulns: []Vuln{
			{CVEIDs: []string{id}},
			{CVEIDs: []string{other}},
			{CVEIDs: []string{id, other}},
		}}},
	}

	t.Setenv("CVE_RESERVATIONS_FILE", reservations)
	t.Setenv("EPSS_ARCHIVE_DIR", "")
	applyHistoricalLEV(context.Background(), &bom)
	require.Equal(t, LEVArchiveDisabled, bom.ReportSource.LEVArchiveStatus)
	require.Empty(t, bom.ComponentInfo["test"].Vulns[0].LEV)

	t.Setenv("EPSS_ARCHIVE_DIR", dir)
	applyHistoricalLEV(context.Background(), &bom)
	require.Equal(t, LEVArchiveConfigured, bom.ReportSource.LEVArchiveStatus)
	findings := bom.ComponentInfo["test"].Vulns
	require.Equal(t, day, findings[0].LEVFirst)
	require.Equal(t, day, findings[0].LEVAsOf)
	require.Equal(t, id, findings[0].LEVCVE)
	require.False(t, findings[0].LEVPartial)
	score, err := strconv.ParseFloat(findings[0].LEV, 64)
	require.NoError(t, err)
	require.InDelta(t, 0.02, score, 1e-12)
	require.Empty(t, findings[1].LEV)
	require.Equal(t, findings[0].LEV, findings[2].LEV)
	require.True(t, findings[2].LEVPartial)
}
