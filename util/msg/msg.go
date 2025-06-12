// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package msg

const (
	RespMsg  = "msg"
	RespErr  = "error"
	RespData = "data"

	ErrInvalidSBOM        = "Unknown SBOM, please check if the SBOM is valid"
	ErrSBOMNotFound       = "SBOM not found"
	ErrComponentNotFound  = "Component not found"
	ErrXMLNotSupport      = "XML-formatted SBOM is currently not supported"
	ErrFileTypeNotSupport = "File type not supported"

	ErrBindingJSON = "Error binding JSON"
	ErrParsingJson = "Error parsing JSON:"
	ErrParsingSPDX = "Error parsing SPDX SBOM"

	ErrMissingParam     = "Missing required parameter: %s"
	ErrInvalidComponent = "Component or SBOM is not found"
)
