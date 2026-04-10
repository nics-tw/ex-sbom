// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	sbomreader "github.com/spdx/tools-golang/json"
)

// Sentinel errors returned by Preview — handlers map these to HTTP status codes.
var (
	ErrXMLNotSupported      = errors.New("xml format is not supported")
	ErrInvalidFileType      = errors.New("unsupported file type")
	ErrInvalidSBOMFormat    = errors.New("unrecognized SBOM format")
	ErrSPDXParseFailed      = errors.New("failed to parse SPDX")
	ErrCycloneDXParseFailed = errors.New("failed to parse CycloneDX")
)

// Preview parses raw SBOM bytes and returns the result without saving to DB.
func (s *Service) Preview(rawData []byte) (FormattedSBOM, string, time.Time, error) {
	switch detectFileType(rawData) {
	case fileTypeJSON: // no-op: proceed to format detection below
	case fileTypeXML:
		return FormattedSBOM{}, "", time.Time{}, ErrXMLNotSupported
	default:
		return FormattedSBOM{}, "", time.Time{}, ErrInvalidFileType
	}

	switch detectSBOMFormat(rawData) {
	case sbomFormatSPDX:
		doc, err := sbomreader.Read(bytes.NewReader(rawData))
		if err != nil {
			return FormattedSBOM{}, "", time.Time{}, fmt.Errorf("%w: %w", ErrSPDXParseFailed, err)
		}
		bom, md5Hash, err := s.PreviewSPDX(doc, rawData)
		return bom, md5Hash, time.Time{}, err

	case sbomFormatCycloneDX:
		cdxData := downgradeCDXSpecVersion(rawData)
		decoder := cdx.NewBOMDecoder(bytes.NewReader(cdxData), cdx.BOMFileFormatJSON)
		var bom cdx.BOM
		if err := decoder.Decode(&bom); err != nil {
			return FormattedSBOM{}, "", time.Time{}, fmt.Errorf("%w: %w", ErrCycloneDXParseFailed, err)
		}
		result, md5Hash, bomTimestamp, err := s.PreviewCDX(bom, rawData)
		return result, md5Hash, bomTimestamp, err

	default:
		return FormattedSBOM{}, "", time.Time{}, ErrInvalidSBOMFormat
	}
}

type fileType int

const (
	fileTypeUnknown fileType = iota
	fileTypeJSON
	fileTypeXML
)

func detectFileType(data []byte) fileType {
	var js json.RawMessage
	if json.Unmarshal(data, &js) == nil {
		return fileTypeJSON
	}
	if _, err := xml.NewDecoder(bytes.NewReader(data)).Token(); err == nil {
		return fileTypeXML
	}
	return fileTypeUnknown
}

type sbomFormat int

const (
	sbomFormatUnknown sbomFormat = iota
	sbomFormatSPDX
	sbomFormatCycloneDX
)

const (
	keySPDXVersion = "spdxVersion"
	keySPDXID      = "SPDXID"
	keyBOMFormat   = "bomFormat"
	keySpecVersion = "specVersion"
	valCycloneDX   = "CycloneDX"
)

// maxSupportedCDXSpec is the highest CycloneDX spec version the decoder library supports.
const maxSupportedCDXSpec = cdx.SpecVersion1_6

// downgradeCDXSpecVersion replaces the specVersion field with the highest supported version
// when the file declares a newer spec that the decoder library does not yet recognise.
// CycloneDX minor versions are backward-compatible, so newer fields are simply ignored.
func downgradeCDXSpecVersion(data []byte) []byte {
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(data, &generic); err != nil {
		return data
	}

	var specVersion string
	if raw, ok := generic[keySpecVersion]; ok {
		_ = json.Unmarshal(raw, &specVersion)
	}
	if specVersion == "" {
		return data
	}

	supported := fmt.Sprintf("%s", maxSupportedCDXSpec)
	if specVersion <= supported {
		return data
	}

	encoded, err := json.Marshal(supported)
	if err != nil {
		return data
	}
	generic[keySpecVersion] = encoded

	downgraded, err := json.Marshal(generic)
	if err != nil {
		return data
	}
	return downgraded
}

func detectSBOMFormat(data []byte) sbomFormat {
	var generic map[string]interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		return sbomFormatUnknown
	}

	if _, ok := generic[keySPDXVersion]; ok {
		if _, ok := generic[keySPDXID]; ok {
			return sbomFormatSPDX
		}
	}

	if f, ok := generic[keyBOMFormat]; ok {
		if s, ok := f.(string); ok && s == valCycloneDX {
			return sbomFormatCycloneDX
		}
	}

	return sbomFormatUnknown
}
