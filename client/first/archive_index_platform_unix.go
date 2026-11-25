//go:build darwin || linux || freebsd

// SPDX-License-Identifier: MIT

package first

import (
	"context"
	"fmt"
	"os"
	"syscall"
)

func archiveIndexIdentity(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() && (!info.Mode().IsRegular() || stat.Nlink != 1) {
		return "", fmt.Errorf("archive path must be a regular file without hard links: %s", path)
	}
	return fmt.Sprintf("%d:%d:%d:%d:%d:%d", stat.Dev, stat.Ino, info.Size(), info.ModTime().UnixNano(),
		archiveChangeTime(stat), info.Mode()), nil
}

func archiveIndexSealedIdentity(path string) (string, error) {
	return archiveIndexIdentity(path)
}

func checkSealedArchiveDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0222 != 0 {
		return fmt.Errorf("archive snapshot directory must be read-only: %s", path)
	}
	return nil
}

func makeArchiveStaging(parent string) (string, error) {
	return os.MkdirTemp(parent, ".lev-index-")
}

func sealArchiveFile(path string) error   { return os.Chmod(path, 0400) }
func unsealArchiveFile(path string) error { return os.Chmod(path, 0600) }

func sealArchiveDirectory(path string) error   { return os.Chmod(path, 0500) }
func unsealArchiveDirectory(path string) error { return os.Chmod(path, 0700) }

func removeArchiveStaging(path string) error {
	_ = unsealArchiveDirectory(path)
	return os.RemoveAll(path)
}

func sealAndPublishArchiveDirectory(ctx context.Context, staging, output string) error {
	if err := sealArchiveDirectory(staging); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return publishArchiveDirectory(staging, output)
}
