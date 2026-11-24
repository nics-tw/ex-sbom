// SPDX-License-Identifier: MIT
//go:build taggedpdf && ((darwin && !ios && arm64) || (linux && !android && (arm64 || amd64)) || (windows && amd64))

package pdf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func taggedExecutable() (string, error) {
	digest, err := taggedAssets.ReadFile(taggedAssetDir + "typst.sha256")
	if err != nil {
		return "", err
	}
	expected := strings.TrimSpace(string(digest))
	if raw, err := hex.DecodeString(expected); err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("invalid embedded Typst SHA-256")
	}
	dir := os.Getenv("EX_SBOM_PDF_CACHE_DIR")
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrCacheUnavailable, err)
		}
		dir = filepath.Join(base, "ex-sbom", "typst")
	}
	dir, err = privateTaggedCache(dir)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCacheUnavailable, err)
	}
	path := filepath.Join(dir, "typst-"+expected+taggedExecutableSuffix)
	if validTaggedExecutable(path, expected) {
		return path, nil
	}

	temp, err := os.CreateTemp(dir, ".typst-*")
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCacheUnavailable, err)
	}
	defer os.Remove(temp.Name())
	hash := sha256.New()
	copyErr := copyTaggedAsset("typst"+taggedExecutableSuffix, io.MultiWriter(temp, hash))
	closeErr := temp.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", fmt.Errorf("%w: %w", ErrCacheUnavailable, closeErr)
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return "", fmt.Errorf("embedded Typst SHA-256 does not match")
	}
	if err := os.Chmod(temp.Name(), taggedExecutableMode); err != nil {
		return "", fmt.Errorf("%w: %w", ErrCacheUnavailable, err)
	}
	if err := os.Rename(temp.Name(), path); err != nil && !validTaggedExecutable(path, expected) {
		return "", fmt.Errorf("%w: %w", ErrCacheUnavailable, err)
	}
	return path, nil
}

func validTaggedExecutable(path, expected string) bool {
	if !privateTaggedExecutable(path) {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	return err == nil && hex.EncodeToString(hash.Sum(nil)) == expected
}
