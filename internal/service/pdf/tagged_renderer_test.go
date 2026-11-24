// SPDX-License-Identifier: MIT
//go:build unit && taggedpdf

package pdf

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTaggedExecutableCache(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "nested", "cache")
	t.Setenv("EX_SBOM_PDF_CACHE_DIR", cache)
	var paths [2]string
	var errors [2]error
	var workers sync.WaitGroup
	for i := range paths {
		workers.Go(func() { paths[i], errors[i] = taggedExecutable() })
	}
	workers.Wait()
	for _, err := range errors {
		require.NoError(t, err)
	}
	path := paths[0]
	require.Equal(t, path, paths[1])
	fresh, err := os.Stat(path)
	require.NoError(t, err)
	reused, err := taggedExecutable()
	require.NoError(t, err)
	cached, err := os.Stat(reused)
	require.NoError(t, err)
	require.True(t, os.SameFile(fresh, cached), "reuse the cached executable")

	require.NoError(t, os.Chmod(path, 0600))
	require.NoError(t, os.WriteFile(path, []byte("damaged cache"), 0600))
	require.NoError(t, os.Chmod(path, taggedExecutableMode))
	path, err = taggedExecutable()
	require.NoError(t, err)
	version, err := exec.Command(path, "--version").CombinedOutput()
	require.NoError(t, err, "%s", version)
	require.Contains(t, string(version), "typst 0.15.1")
	files, err := os.ReadDir(cache)
	require.NoError(t, err)
	require.Len(t, files, 1)
}

func TestTaggedExecutableRejectsSymlinkCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reparse-point checks run in the Windows cache test")
	}
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	require.NoError(t, os.Symlink(dir, cache))
	t.Setenv("EX_SBOM_PDF_CACHE_DIR", cache)
	_, err := taggedExecutable()
	require.ErrorContains(t, err, "service user with mode 0700")
}

func TestTaggedExecutableRejectsWritableParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACL checks run in the Windows cache test")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0777))
	t.Setenv("EX_SBOM_PDF_CACHE_DIR", filepath.Join(dir, "cache"))
	_, err := taggedExecutable()
	require.ErrorContains(t, err, "writable by another user")
}

func TestTaggedReportQueueHonorsRequestCancellation(t *testing.T) {
	taggedRenderSlot <- struct{}{}
	defer func() { <-taggedRenderSlot }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, GenerateContext(ctx, io.Discard, Report{}), context.DeadlineExceeded)
}

func TestTaggedReportQueueHonorsConfiguredTimeout(t *testing.T) {
	t.Setenv("EX_SBOM_PDF_TIMEOUT", "20ms")
	taggedRenderSlot <- struct{}{}
	defer func() { <-taggedRenderSlot }()
	require.ErrorIs(t, Generate(io.Discard, Report{}), context.DeadlineExceeded)
}

func TestTaggedReportIncludesBoundedRendererDiagnostics(t *testing.T) {
	t.Setenv("EX_SBOM_PDF_CACHE_DIR", filepath.Join(t.TempDir(), "cache"))
	original := taggedTemplate
	t.Cleanup(func() { taggedTemplate = original })
	taggedTemplate = []byte(`#panic("diagnostic marker ` + strings.Repeat("x", 8192) + `")`)
	err := Generate(io.Discard, Report{Language: English})
	require.ErrorContains(t, err, "diagnostic marker")
	require.Less(t, len(err.Error()), 4300)
}
