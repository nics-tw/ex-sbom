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

	"github.com/stretchr/testify/require"
)

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

func TestReadCVEReservationsRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reservations.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0600))
	require.NoError(t, os.Truncate(path, maxReservationBytes+1))
	dates, err := readCVEReservations(context.Background(), path, []string{"CVE-2026-0001"})
	require.ErrorContains(t, err, "invalid CVE reservation file type or size")
	require.Empty(t, dates)
}
