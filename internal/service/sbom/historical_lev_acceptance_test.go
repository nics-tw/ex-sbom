//go:build unit

// SPDX-License-Identifier: MIT

package ssbom

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"ex-sbom/client/cisa"
	"ex-sbom/client/first"

	"github.com/stretchr/testify/require"
)

// Run with -v -count=1 in a new process. Time the verified index before any
// other archive reads, then exercise import and compare with the raw archive.
func TestHistoricalLEVOfficialArchiveAcceptance(t *testing.T) {
	snapshot := os.Getenv("EX_SBOM_LEV_ACCEPT_SNAPSHOT")
	if snapshot == "" {
		t.Skip("official LEV fixture not supplied")
	}
	source := os.Getenv("EX_SBOM_LEV_ACCEPT_SOURCE")
	cutoff := os.Getenv("EX_SBOM_LEV_ACCEPT_CUTOFF")
	idsPath := os.Getenv("EX_SBOM_LEV_ACCEPT_CVES")
	require.NotEmpty(t, source)
	require.NotEqual(t, source, snapshot)
	asOf, err := time.Parse(time.DateOnly, cutoff)
	require.NoError(t, err)
	input, err := os.ReadFile(idsPath)
	require.NoError(t, err)
	ids := strings.Fields(string(input))
	require.Len(t, ids, 46)
	findings := make([]Vuln, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		require.True(t, cisa.IsCVE(id), "invalid CVE in acceptance input")
		require.False(t, seen[id], "duplicate CVE in acceptance input")
		seen[id] = true
		findings = append(findings, Vuln{ID: id, CVEIDs: []string{id}})
	}

	t.Setenv("EPSS_ARCHIVE_DIR", snapshot)
	snapshotReservations := ""
	path := filepath.Join(snapshot, first.ArchiveIndexReservations)
	if _, err := os.Stat(path); err == nil {
		snapshotReservations = path
	} else {
		require.ErrorIs(t, err, os.ErrNotExist)
	}
	t.Setenv("CVE_RESERVATIONS_FILE", snapshotReservations)
	queried := asOf.AddDate(0, 0, 1)
	sample := FormattedSBOM{
		ReportSource:  &ReportSource{QueriedAt: &queried},
		ComponentInfo: map[string]Component{"archive": {Vulns: findings}},
	}

	start := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(historicalLEVBudget))
	indexed, err := first.LookupArchiveIndex(ctx, snapshot, snapshotReservations, cutoff, ids)
	elapsed := time.Since(start)
	cancel()
	require.NoError(t, err, "acceptance needs a verified index")
	require.Less(t, elapsed, historicalLEVBudget)

	importStart := time.Now()
	applyHistoricalLEV(context.Background(), &sample)
	importElapsed := time.Since(importStart)

	reservations := os.Getenv("EX_SBOM_LEV_ACCEPT_RESERVATIONS")
	var dates map[string]string
	if reservations != "" {
		dates, err = first.ReadCVEReservations(context.Background(), reservations, ids)
		if err != nil {
			require.NotNil(t, dates, "unable to read the reference reservation file")
			t.Logf("reference reservations contain rejected entries: %v", err)
		}
	}
	refStart := time.Now()
	reference, err := first.ArchiveLEVWithReservations(source, first.FirstArchiveDay, cutoff, ids, dates)
	refElapsed := time.Since(refStart)
	if err != nil {
		require.NotNil(t, reference, "unable to read the reference archive")
		t.Logf("reference archive includes unusable input: %v", err)
	}
	require.NotEmpty(t, reference, "fixture must include usable historical evidence")
	require.Equal(t, reference, indexed)

	expected := FormattedSBOM{ComponentInfo: map[string]Component{"archive": {Vulns: findings}}}
	setHistoricalLEV(&expected, reference)
	require.Equal(t, expected.ComponentInfo, sample.ComponentInfo)

	var partial int
	for _, row := range indexed {
		if row.Partial {
			partial++
		}
	}
	manifest, err := os.ReadFile(filepath.Join(snapshot, "lev-index.json"))
	require.NoError(t, err)
	t.Logf("%s/%s %s cutoff=%s cves_sha256=%x manifest_sha256=%x cves=%d complete=%d lower_bound=%d unavailable=%d verified_index=%s subsequent_import=%s raw_reference=%s",
		runtime.GOOS, runtime.GOARCH, runtime.Version(), cutoff, sha256.Sum256(input),
		sha256.Sum256(manifest), len(ids), len(indexed)-partial, partial, len(ids)-len(indexed), elapsed, importElapsed, refElapsed)
	if report := os.Getenv("EX_SBOM_LEV_ACCEPT_REPORT"); report != "" {
		results := struct {
			Cutoff    string                         `json:"cutoff"`
			Elapsed   time.Duration                  `json:"verified_index_ns"`
			Reference time.Duration                  `json:"raw_reference_ns"`
			Verified  []Vuln                         `json:"verified_findings"`
			Index     map[string]first.HistoricalLEV `json:"index_results"`
		}{cutoff, elapsed, refElapsed, sample.ComponentInfo["archive"].Vulns, indexed}
		encoded, err := json.MarshalIndent(results, "", "  ")
		require.NoError(t, err)
		file, err := os.OpenFile(report, os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0600)
		require.NoError(t, err)
		_, writeErr := file.Write(append(encoded, '\n'))
		require.NoError(t, file.Close())
		require.NoError(t, writeErr)
	}
}
