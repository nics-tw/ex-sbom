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

func TestArchiveIndexRequiresReadOnlyWindowsDACL(t *testing.T) {
	ctx := context.Background()
	source := t.TempDir()
	const cve = "CVE-2021-1001"
	writeArchiveDay(t, source, FirstArchiveDay, "cve,epss\n"+cve+",0.4\n")
	reservations := filepath.Join(source, "reservations.json")
	require.NoError(t, os.WriteFile(reservations, []byte(`{"CVE-2021-1001":"2021-04-14"}`), 0600))

	for _, name := range []string{archiveDayName(FirstArchiveDay), ArchiveIndexReservations, archiveIndexManifestName, archiveIndexDBName} {
		t.Run(name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "snapshot")
			t.Cleanup(func() { require.NoError(t, removeArchiveStaging(output)) })
			require.NoError(t, BuildArchiveIndex(ctx, source, reservations, FirstArchiveDay, output))
			require.NoError(t, checkSealedArchiveDirectory(output))
			sealedReservations := filepath.Join(output, ArchiveIndexReservations)
			result, err := LookupArchiveIndex(ctx, output, sealedReservations, FirstArchiveDay, []string{cve})
			require.NoError(t, err)
			require.Contains(t, result, cve)

			path := filepath.Join(output, name)
			_, err = sealedArchiveFileIdentity(path, archiveIndexDatabaseLimit)
			require.NoError(t, err)
			require.NoError(t, setArchiveWindowsPathDACL(path, "FA", false, false))
			info, err := os.Stat(path)
			require.NoError(t, err)
			require.Zero(t, info.Mode().Perm()&0222)
			_, err = sealedArchiveFileIdentity(path, archiveIndexDatabaseLimit)
			require.ErrorContains(t, err, "read-only DACL")
			result, err = LookupArchiveIndex(ctx, output, sealedReservations, FirstArchiveDay, []string{cve})
			require.Error(t, err)
			require.Nil(t, result)
		})
	}
}
