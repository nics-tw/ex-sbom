// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package ssbom

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ex-sbom/client/cisa"

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
	// ErrScanFailed marks a vulnerability scan that could not run: the result
	// must never be presented (or saved) as a clean zero-vulnerability analysis.
	ErrScanFailed = errors.New("vulnerability scan failed")
)

// Preview parses raw SBOM bytes and returns the result without saving to DB.
func (s *Service) Preview(rawData []byte) (FormattedSBOM, string, time.Time, error) {
	return s.PreviewContext(context.Background(), rawData)
}

// PreviewContext applies the request deadline to historical archive enrichment.
func (s *Service) PreviewContext(ctx context.Context, rawData []byte) (FormattedSBOM, string, time.Time, error) {
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
		bom, _, err := s.PreviewSPDX(doc, rawData)
		if err != nil {
			return FormattedSBOM{}, "", time.Time{}, err
		}
		setReportSpecification(&bom, rawData, keySPDXVersion, "")
		applyKEV(&bom, cisa.Current)
		applyHistoricalLEV(ctx, &bom)
		sortFormattedSBOM(&bom)
		return bom, HashSBOM(bom), spdxTimestamp(doc), nil

	case sbomFormatCycloneDX:
		cdxData := downgradeCDXSpecVersion(rawData)
		decoder := cdx.NewBOMDecoder(bytes.NewReader(cdxData), cdx.BOMFileFormatJSON)
		var bom cdx.BOM
		if err := decoder.Decode(&bom); err != nil {
			return FormattedSBOM{}, "", time.Time{}, fmt.Errorf("%w: %w", ErrCycloneDXParseFailed, err)
		}
		// Scan the same (possibly downgraded) representation the decoder accepted,
		// so the scanner cannot reject bytes the parser already validated.
		result, _, bomTimestamp, err := s.PreviewCDX(bom, cdxData)
		if err != nil {
			return result, "", bomTimestamp, err
		}
		setReportSpecification(&result, rawData, keySpecVersion, "CycloneDX ")
		applyKEV(&result, cisa.Current)
		applyHistoricalLEV(ctx, &result)
		sortFormattedSBOM(&result)
		return result, HashSBOM(result), bomTimestamp, nil

	default:
		return FormattedSBOM{}, "", time.Time{}, ErrInvalidSBOMFormat
	}
}

// Use the original input's specification, even when the scanner parsed a
// supported representation of a newer CycloneDX document.
func setReportSpecification(bom *FormattedSBOM, raw []byte, key, prefix string) {
	var metadata map[string]json.RawMessage
	var version string
	if bom.ReportSource != nil && json.Unmarshal(raw, &metadata) == nil &&
		json.Unmarshal(metadata[key], &version) == nil && version != "" {
		bom.ReportSource.Specification = prefix + version
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
const maxSupportedCDXSpec = cdx.SpecVersion1_7

// downgradeCDXSpecVersion leaves supported inputs intact. For newer versions,
// it substitutes the highest supported version for a best-effort import.
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
	if compareSpecVersions(specVersion, supported) <= 0 {
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

// compareSpecVersions compares two dotted version strings (e.g. "1.6", "1.10")
// numerically component by component. It returns -1 if a < b, 0 if a == b, and
// 1 if a > b. Non-numeric or missing components are treated as 0.
func compareSpecVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	n := len(aParts)
	if len(bParts) > n {
		n = len(bParts)
	}

	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(aParts) {
			av, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bv, _ = strconv.Atoi(bParts[i])
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}

	return 0
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
