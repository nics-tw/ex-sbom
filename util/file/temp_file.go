// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package file

import "os"

const (
	// DefaultCDXName is the fixed filename used when writing a CycloneDX SBOM for OSV scanning.
	DefaultCDXName = "bom.json"
	// DefaultSPDXName is the fixed filename used when writing an SPDX SBOM for OSV scanning.
	DefaultSPDXName = "sbom.spdx.json"

	defaultPermissions = 0644
)

type (
	FileInput struct {
		IsCDX bool
		Data  []byte
	}
)

func CopyAndCreate(input FileInput) (string, error) {
	var name string
	if input.IsCDX {
		name = DefaultCDXName
	} else {
		name = DefaultSPDXName
	}

	if err := os.WriteFile(name, input.Data, defaultPermissions); err != nil {
		return "", err
	}

	return name, nil
}

func Delete(name string) error {
	if err := os.Remove(name); err != nil {
		return err
	}

	return nil
}
