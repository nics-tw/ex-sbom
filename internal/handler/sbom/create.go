// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package sbom

type SBOMType int

const (
	SBOMUnknown SBOMType = iota
	SBOMSPDX
	SBOMCycloneDX
)

type FileType int

const (
	Unknown FileType = iota
	JSON
	XML
)

const (
	version   = "spdxVersion"
	id        = "SPDXID"
	format    = "bomFormat"
	cyclonedx = "CycloneDX"
)