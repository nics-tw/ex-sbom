//go:build unit

package first

import (
	"compress/gzip"
	"os"
	"path/filepath"
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
	_, err = ArchiveLEV(dir, "2023-01-01", "2023-02-01", cves)
	require.ErrorContains(t, err, "2023-01-31")
}
