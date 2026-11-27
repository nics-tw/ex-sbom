//go:build unit

// SPDX-License-Identifier: MIT

package first

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadCVEReservationsSelectsRequestedOrAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reservations.json")
	const contents = `{"CVE-2026-0001":"2026-01-01","CVE-2026-0002":false,"CVE-2026-0003":"2026-01-02","CVE-2026-0003":"2026-01-03","CVE-2026-0004":"2026-02-29","CVE-2026-0005":"2026-01-03"}`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0600))
	ctx := context.Background()
	got, err := ReadCVEReservations(ctx, path, nil)
	require.ErrorContains(t, err, "ignored 3 invalid or duplicate")
	require.Equal(t, "2026-01-01", got["CVE-2026-0001"])
	require.Equal(t, "2026-01-03", got["CVE-2026-0005"])
	require.Empty(t, got["CVE-2026-0002"])
	require.Empty(t, got["CVE-2026-0003"])
	require.Empty(t, got["CVE-2026-0004"])
	got, err = ReadCVEReservations(ctx, path, []string{"CVE-2026-0001"})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"CVE-2026-0001": "2026-01-01"}, got)
}

func TestReadCVEReservationsRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reservations.json")
	require.NoError(t, os.WriteFile(path, nil, 0600))
	require.NoError(t, os.Truncate(path, maxReservationBytes+1))
	dates, err := ReadCVEReservations(context.Background(), path, []string{"CVE-2026-0001"})
	require.ErrorContains(t, err, "invalid CVE reservation file")
	require.Empty(t, dates)
}
