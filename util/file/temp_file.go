// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package file

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultCDXName is the fixed filename used when writing a CycloneDX SBOM for OSV scanning.
	// The name is significant: osv-scanner detects the SBOM format from it.
	DefaultCDXName = "bom.json"
	// DefaultSPDXName is the fixed filename used when writing an SPDX SBOM for OSV scanning.
	DefaultSPDXName = "sbom.spdx.json"

	// tempDirPrefix marks per-request scan directories so Delete can recognise
	// and remove them as a whole.
	tempDirPrefix = "ex-sbom-scan-"

	defaultPermissions = 0644
)

type (
	FileInput struct {
		IsCDX bool
		Data  []byte
	}
)

// CopyAndCreate writes the SBOM into a unique per-call temp directory and
// returns the file path. The canonical filename is kept (osv-scanner infers
// the format from it) while the unique directory isolates concurrent requests
// from overwriting or deleting each other's files.
func CopyAndCreate(input FileInput) (string, error) {
	var name string
	if input.IsCDX {
		name = DefaultCDXName
	} else {
		name = DefaultSPDXName
	}

	dir, err := os.MkdirTemp("", tempDirPrefix+"*")
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, input.Data, defaultPermissions); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}

	return path, nil
}

// Delete removes the path created by CopyAndCreate. When the file lives in a
// per-request scan directory the whole directory is removed; any other path
// keeps the original single-file semantics.
func Delete(name string) error {
	dir := filepath.Dir(name)
	if strings.HasPrefix(filepath.Base(dir), tempDirPrefix) {
		return os.RemoveAll(dir)
	}

	if err := os.Remove(name); err != nil {
		return err
	}

	return nil
}
