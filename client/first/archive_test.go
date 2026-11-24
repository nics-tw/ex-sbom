//go:build unit

package first

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestArchiveLEV(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	for offset := 0; offset <= 31; offset++ {
		day := start.AddDate(0, 0, offset).Format(time.DateOnly)
		file, err := os.Create(filepath.Join(dir, "epss_scores-"+day+".csv.gz"))
		require.NoError(t, err)
		stream := gzip.NewWriter(file)
		header := "cve,epss\n"
		if offset > 0 {
			header = "#model_version:v1,score_date:" + day + "T00:00:00+0000\ncve,epss\n"
		}
		_, err = stream.Write([]byte(header + "CVE-2023-0001,0.3\n"))
		require.NoError(t, err)
		if offset > 0 {
			_, err = stream.Write([]byte("CVE-2023-0002,0\n"))
			require.NoError(t, err)
		}
		require.NoError(t, stream.Close())
		require.NoError(t, file.Close())
	}
	cves := []string{"CVE-2023-0001", "CVE-2023-0002"}
	got, err := ArchiveLEV(dir, "2023-01-01", "2023-02-01", cves)
	require.NoError(t, err)
	require.Equal(t, "2023-01-01", got[cves[0]].First)
	require.Equal(t, "2023-01-02", got[cves[1]].First)
	require.InDelta(t, 0.314, got[cves[0]].Score, 1e-12)
	require.Zero(t, got[cves[1]].Score)

	require.NoError(t, os.Remove(filepath.Join(dir, "epss_scores-2023-01-31.csv.gz")))
	got, err = ArchiveLEV(dir, "2023-01-01", "2023-02-01", cves)
	require.NoError(t, err)
	require.True(t, got[cves[0]].Partial)
	require.InDelta(t, 0.3, got[cves[0]].Score, 1e-12)
	require.False(t, got[cves[1]].Partial)
	require.Zero(t, got[cves[1]].Score)

	require.NoError(t, os.Remove(filepath.Join(dir, "epss_scores-2023-01-01.csv.gz")))
	got, err = ArchiveLEV(dir, "2023-01-01", "2023-02-01", cves)
	require.NoError(t, err)
	require.Empty(t, got, "a gap before the first observed score leaves the window anchor unverified")
	got, err = ArchiveLEVWithReservations(dir, "2023-01-01", "2023-02-01", cves, map[string]string{
		cves[1]: "2023-01-02",
	})
	require.NoError(t, err)
	require.NotContains(t, got, cves[0])
	require.Equal(t, "2023-01-02", got[cves[1]].First)
	require.False(t, got[cves[1]].Partial)
}

func TestArchiveLEVIsolatesCorruptRows(t *testing.T) {
	dir := t.TempDir()
	writeArchiveDay(t, dir, "2023-01-01", "cve,epss\nCVE-2023-0001,0.3\nCVE-2023-0002,0.2\nCVE-2023-0002,0.9\nCVE-2023-0003,broken\nCVE-2023-0004,0.1,unexpected\nCVE-2023-0006,"+strings.Repeat("9", 8192)+"\nCVE-2023-0007,0.5\n")
	writeArchiveDay(t, dir, "2023-01-02", "cve,epss\nCVE-2023-0002,0.2\nCVE-2023-0003,0.2\nCVE-2023-0004,0.2\nCVE-2023-0005,0.6\n")
	cves := []string{"CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003", "CVE-2023-0004", "CVE-2023-0005", "CVE-2023-0006", "CVE-2023-0007"}
	got, err := ArchiveLEV(dir, "2023-01-01", "2023-01-02", cves)
	require.Error(t, err)
	require.Len(t, got, 3)
	require.Equal(t, "2023-01-01", got[cves[0]].First)
	require.False(t, got[cves[0]].Partial)
	require.Equal(t, "2023-01-02", got[cves[4]].First)
	require.False(t, got[cves[4]].Partial)
	require.Equal(t, "2023-01-01", got[cves[6]].First)
	require.False(t, got[cves[6]].Partial)
}

func TestArchiveLEVUnusableDaysKeepKnownWindows(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(*testing.T, string, string)
	}{
		{"broken gzip", func(t *testing.T, dir, day string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "epss_scores-"+day+".csv.gz"), []byte("broken"), 0600))
		}},
		{"invalid header", func(t *testing.T, dir, day string) {
			writeArchiveDay(t, dir, day, "cve,wrong\nCVE-2023-0001,0.9\n")
		}},
		{"oversized header", func(t *testing.T, dir, day string) {
			writeArchiveDay(t, dir, day, "cve,"+strings.Repeat("a", 8192)+"\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			const id = "CVE-2023-0001"
			writeArchiveDay(t, dir, "2023-01-01", "cve,epss\n"+id+",0.3\n")
			tc.write(t, dir, "2023-01-31")
			got, err := ArchiveLEV(dir, "2023-01-01", "2023-01-31", []string{id})
			require.Error(t, err)
			require.True(t, got[id].Partial)
			require.InDelta(t, 0.3, got[id].Score, 1e-12)
		})
	}
}

func TestArchiveLEVRejectsOversizedDecompressedData(t *testing.T) {
	dir := t.TempDir()
	const day, id = "2023-01-01", "CVE-2023-0001"
	file, err := os.Create(filepath.Join(dir, "epss_scores-"+day+".csv.gz"))
	require.NoError(t, err)
	stream := gzip.NewWriter(file)
	_, err = stream.Write([]byte("cve,epss,percentile\n" + id + ",0.9,0.9\n"))
	require.NoError(t, err)
	row := []byte("CVE-2023-5555,0.1,0." + strings.Repeat("0", 2000) + "\n")
	chunk := bytes.Repeat(row, 512)
	for range maxArchiveBytes/len(chunk) + 1 {
		_, err := stream.Write(chunk)
		require.NoError(t, err)
	}
	require.NoError(t, stream.Close())
	require.NoError(t, file.Close())

	got, err := ArchiveLEV(dir, day, day, []string{id})
	require.Error(t, err)
	require.Empty(t, got)
}

func TestArchiveLEVRefreshesReplacedDailyFile(t *testing.T) {
	dir := t.TempDir()
	const day, id = "2023-01-01", "CVE-2023-0001"
	writeArchiveDay(t, dir, day, "cve,epss\n"+id+",0.3\n")
	got, err := ArchiveLEV(dir, day, day, []string{id})
	require.NoError(t, err)
	require.InDelta(t, 0.01, got[id].Score, 1e-12)

	replacement := t.TempDir()
	writeArchiveDay(t, replacement, day, "cve,epss\n"+id+",0.6\n")
	filename := "epss_scores-" + day + ".csv.gz"
	require.NoError(t, os.Rename(filepath.Join(replacement, filename), filepath.Join(dir, filename)))
	got, err = ArchiveLEV(dir, day, day, []string{id})
	require.NoError(t, err)
	require.InDelta(t, 0.02, got[id].Score, 1e-12)
}

func TestArchiveLEVRespectsCancellation(t *testing.T) {
	dir := t.TempDir()
	const day, id = "2023-01-01", "CVE-2023-0001"
	writeArchiveDay(t, dir, day, "cve,epss\n"+id+",0.3\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := ArchiveLEVContext(ctx, dir, day, day, []string{id}, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, got)
}

func writeArchiveDay(t *testing.T, dir, day, content string) {
	t.Helper()
	file, err := os.Create(filepath.Join(dir, "epss_scores-"+day+".csv.gz"))
	require.NoError(t, err)
	stream := gzip.NewWriter(file)
	_, err = stream.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	require.NoError(t, file.Close())
}
