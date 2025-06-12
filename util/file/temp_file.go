// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package file

import "os"

const (
	// Currently the file naming pattern that consumed by the scalibre is limited,
	// here apply the most acceptble name for cyclonedx sbom file.
	// as for the spdx format sbom, currently we apply the original file name
	DefaultName = "bom.json"

	defaultPermissions = 0644
)

type (
	FileInput struct {
		Name  string
		IsCDX bool
		Data  []byte
	}
)

func CopyAndCreate(input FileInput) (string, error) {
	var name string
	if input.IsCDX {
		name = DefaultName
	} else {
		name = input.Name
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
