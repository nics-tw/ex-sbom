//go:build unit

// SPDX-License-Identifier: MIT

package first

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestArchiveIndexMatchesArchive(t *testing.T) {
	source := t.TempDir()
	output := filepath.Join(t.TempDir(), "snapshot")
	t.Cleanup(func() { require.NoError(t, removeArchiveStaging(output)) })
	first, err := time.Parse(time.DateOnly, FirstArchiveDay)
	require.NoError(t, err)
	const cutoff = "2021-05-17"
	const complete, partial, earlyGap, broken, zero = "CVE-2021-1001", "CVE-2021-1002", "CVE-2021-1003", "CVE-2021-1004", "CVE-2021-1005"
	const unknown, future, afterMalformed = "CVE-2021-1006", "CVE-2021-1007", "CVE-2021-1008"
	for offset := 1; offset <= 33; offset++ {
		day := first.AddDate(0, 0, offset).Format(time.DateOnly)
		if offset == 32 {
			oversized := filepath.Join(source, archiveDayName(day))
			require.NoError(t, os.WriteFile(oversized, nil, 0600))
			require.NoError(t, os.Truncate(oversized, maxArchiveBytes+1))
			continue
		}
		contents := "cve,epss\n" + earlyGap + ",0.8\n"
		switch offset {
		case 1:
			contents += complete + ",0.25\n" + broken + ",0.8\n" + broken + ",0.9\n" + future + ",0.9\n"
		case 2:
			contents += partial + ",0.6\n" + zero + ",0\n" + "unidentified,0.9\n"
		case 3:
			contents += afterMalformed + ",0.8\n"
		case 31:
			contents += complete + ",0.5\n"
		case 33:
			contents += afterMalformed + ",0.8\n"
		}
		writeArchiveDay(t, source, day, contents)
	}
	reservations := filepath.Join(t.TempDir(), "cves.json")
	require.NoError(t, os.WriteFile(reservations, []byte(`{"CVE-2021-1001":"2021-04-15","CVE-2021-1002":"2021-04-16","CVE-2021-1004":"2021-04-15","CVE-2021-1005":"2021-04-16","CVE-2021-1007":"2021-05-18","CVE-2021-1008":"2021-04-15"}`), 0600))
	cves := []string{complete, partial, earlyGap, broken, zero, unknown, future, afterMalformed}
	ctx := context.Background()
	require.NoError(t, BuildArchiveIndex(ctx, source, reservations, cutoff, output))

	sealedReservations := filepath.Join(output, ArchiveIndexReservations)
	got, err := LookupArchiveIndex(ctx, output, sealedReservations, cutoff, cves)
	require.NoError(t, err)
	dates, err := ReadCVEReservations(ctx, reservations, cves)
	require.NoError(t, err)
	want, err := ArchiveLEVWithReservations(source, FirstArchiveDay, cutoff, cves, dates)
	require.ErrorContains(t, err, "invalid or duplicate")
	require.Equal(t, want, got)
	require.Len(t, got, 3)
	require.False(t, got[complete].Partial)
	require.True(t, got[partial].Partial)
	require.Zero(t, got[zero].Score)
	require.True(t, got[zero].Partial)

	_, err = LookupArchiveIndex(ctx, output, sealedReservations, "2021-05-16", cves)
	require.Error(t, err)
	_, err = LookupArchiveIndex(ctx, output, "", cutoff, cves)
	require.Error(t, err)
	_, err = LookupArchiveIndex(ctx, output, reservations, cutoff, cves)
	require.Error(t, err)
	require.ErrorIs(t, BuildArchiveIndex(ctx, source, reservations, cutoff, output), os.ErrExist)
}

func TestArchiveIndexBuildRejectsChangedSources(t *testing.T) {
	cve := "CVE-2021-1001"
	dir := t.TempDir()
	writeArchiveDay(t, dir, FirstArchiveDay, "cve,epss\n"+cve+",0.4\n")
	name := archiveDayName(FirstArchiveDay)
	info, err := captureArchiveSource(filepath.Join(dir, name))
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(dir, name)))
	writeArchiveDay(t, dir, FirstArchiveDay, "cve,epss\n"+cve+",0.8\n")
	require.ErrorContains(t, verifyArchiveSource(filepath.Join(dir, name), info), "changed")
	name = archiveDayName("2021-04-15")
	info, err = captureArchiveSource(filepath.Join(dir, name))
	require.NoError(t, err)
	require.Nil(t, info.info)
	writeArchiveDay(t, dir, "2021-04-15", "cve,epss\n")
	require.ErrorContains(t, verifyArchiveSource(filepath.Join(dir, name), info), "changed")
}

func TestArchiveIndexPublishDoesNotReplaceConcurrentSnapshot(t *testing.T) {
	source := t.TempDir()
	writeArchiveDay(t, source, FirstArchiveDay, "cve,epss\nCVE-2021-1001,0.4\n")
	dir := t.TempDir()
	output := filepath.Join(dir, "snapshot")
	t.Cleanup(func() { require.NoError(t, removeArchiveStaging(output)) })
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			results <- BuildArchiveIndex(context.Background(), source, "", FirstArchiveDay, output)
		})
	}
	wg.Wait()
	a, b := <-results, <-results
	if a != nil {
		a, b = b, a
	}
	require.NoError(t, a)
	require.True(t, errors.Is(b, os.ErrExist), "%v", b)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestArchiveIndexRejectsChangedSealedFiles(t *testing.T) {
	source := t.TempDir()
	name := archiveDayName(FirstArchiveDay)
	writeArchiveDay(t, source, FirstArchiveDay, "cve,epss\nCVE-2021-1001,0.4\n")
	for _, corrupted := range []string{name, archiveIndexDBName} {
		t.Run(corrupted, func(t *testing.T) {
			ctx := context.Background()
			output := filepath.Join(t.TempDir(), "snapshot")
			require.NoError(t, BuildArchiveIndex(ctx, source, "", FirstArchiveDay, output))
			t.Cleanup(func() { require.NoError(t, removeArchiveStaging(output)) })
			path := filepath.Join(output, corrupted)
			require.NoError(t, unsealArchiveDirectory(output))
			prior, err := os.Stat(path)
			require.NoError(t, err)
			substitute := filepath.Join(output, ".replacement")
			require.NoError(t, os.WriteFile(substitute, make([]byte, prior.Size()), 0600))
			require.NoError(t, os.Chtimes(substitute, prior.ModTime(), prior.ModTime()))
			require.NoError(t, unsealArchiveFile(path))
			require.NoError(t, os.Remove(path))
			require.NoError(t, os.Rename(substitute, path))
			require.NoError(t, sealArchiveFile(path))
			require.NoError(t, sealArchiveDirectory(output))
			got, err := LookupArchiveIndex(ctx, output, "", FirstArchiveDay, []string{"CVE-2021-1001"})
			require.Error(t, err)
			require.Nil(t, got)
		})
	}
}
