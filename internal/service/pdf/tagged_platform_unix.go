// SPDX-License-Identifier: MIT
//go:build taggedpdf && ((darwin && !ios && arm64) || (linux && !android && (arm64 || amd64)))

package pdf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const (
	taggedExecutableSuffix = ""
	taggedExecutableMode   = 0500
)

func taggedWorkspaceRoot(string) string { return "" }

func configureTaggedCommand(*exec.Cmd, string) {}

func privateTaggedCache(dir string) (string, error) {
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("cache directory must be an absolute path")
	}
	dir = filepath.Clean(dir)
	parts := []string{filepath.Base(dir)}
	parent := filepath.Dir(dir)
	for {
		resolved, err := filepath.EvalSymlinks(parent)
		if err == nil {
			parent = resolved
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parts = append(parts, filepath.Base(parent))
		parent = filepath.Dir(parent)
	}
	// An untrusted writable parent could swap the path between verification and execution.
	uid := uint32(os.Geteuid())
	for p := parent; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		mode, owner := info.Mode(), info.Sys().(*syscall.Stat_t).Uid
		if !info.IsDir() || (owner != 0 && owner != uid) || (mode.Perm()&0022 != 0 && mode&os.ModeSticky == 0) {
			return "", fmt.Errorf("cache parent directory %q is writable by another user or has an untrusted owner", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	for i := len(parts) - 1; i >= 0; i-- {
		parent = filepath.Join(parent, parts[i])
		info, err := os.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(parent, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return "", err
			}
			info, err = os.Lstat(parent)
		}
		if err != nil {
			return "", err
		}
		if info.Mode() != os.ModeDir|0700 || info.Sys().(*syscall.Stat_t).Uid != uid {
			return "", fmt.Errorf("cache directory %q must be owned by the service user with mode 0700", parent)
		}
	}
	return parent, nil
}

func privateTaggedExecutable(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode() == taggedExecutableMode && info.Sys().(*syscall.Stat_t).Uid == uint32(os.Geteuid())
}
