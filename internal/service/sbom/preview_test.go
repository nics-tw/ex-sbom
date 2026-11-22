// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package ssbom

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scancdx "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	sbomreader "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSPDXTimestamp(t *testing.T) {
	fixture, err := os.Open("testdata/spdx-id-not-name.spdx.json")
	require.NoError(t, err)
	defer fixture.Close()
	doc, err := sbomreader.Read(fixture)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), spdxTimestamp(doc))
	assert.True(t, spdxTimestamp(&spdx.Document{}).IsZero())
	doc.CreationInfo.Created = "invalid"
	assert.True(t, spdxTimestamp(doc).IsZero())
}

func TestDetectSBOMFormat(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected sbomFormat
	}{
		{
			name: "valid SPDX SBOM",
			data: []byte(`{
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "test-document"
            }`),
			expected: sbomFormatSPDX,
		},
		{
			name: "SPDX with only version field",
			data: []byte(`{
                "spdxVersion": "SPDX-2.3",
                "name": "test-document"
            }`),
			expected: sbomFormatUnknown,
		},
		{
			name: "SPDX with only SPDXID field",
			data: []byte(`{
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "test-document"
            }`),
			expected: sbomFormatUnknown,
		},
		{
			name: "valid CycloneDX SBOM",
			data: []byte(`{
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "version": 1
            }`),
			expected: sbomFormatCycloneDX,
		},
		{
			name: "CycloneDX with wrong format value",
			data: []byte(`{
                "bomFormat": "WrongFormat",
                "specVersion": "1.4",
                "version": 1
            }`),
			expected: sbomFormatUnknown,
		},
		{
			name: "CycloneDX with non-string format value",
			data: []byte(`{
                "bomFormat": 123,
                "specVersion": "1.4",
                "version": 1
            }`),
			expected: sbomFormatUnknown,
		},
		{
			name: "missing bomFormat field",
			data: []byte(`{
                "specVersion": "1.4",
                "version": 1
            }`),
			expected: sbomFormatUnknown,
		},
		{
			name: "invalid JSON",
			data: []byte(`{
                "bomFormat": "CycloneDX",
                "specVersion": "1.4"
                "version": 1
            }`),
			expected: sbomFormatUnknown,
		},
		{
			name:     "empty JSON object",
			data:     []byte(`{}`),
			expected: sbomFormatUnknown,
		},
		{
			name: "JSON array instead of object",
			data: []byte(`[
                {"bomFormat": "CycloneDX"}
            ]`),
			expected: sbomFormatUnknown,
		},
		{
			name:     "completely invalid JSON",
			data:     []byte(`not json at all`),
			expected: sbomFormatUnknown,
		},
		{
			name:     "empty data",
			data:     []byte(``),
			expected: sbomFormatUnknown,
		},
		{
			name:     "null JSON",
			data:     []byte(`null`),
			expected: sbomFormatUnknown,
		},
		{
			name: "complex SPDX with additional fields",
			data: []byte(`{
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "complex-document",
                "documentNamespace": "https://example.com/spdx",
                "packages": [],
                "relationships": []
            }`),
			expected: sbomFormatSPDX,
		},
		{
			name: "complex CycloneDX with additional fields",
			data: []byte(`{
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "version": 1,
                "metadata": {
                    "timestamp": "2023-01-01T00:00:00Z"
                },
                "components": []
            }`),
			expected: sbomFormatCycloneDX,
		},
		{
			name: "both SPDX and CycloneDX fields (SPDX takes precedence)",
			data: []byte(`{
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "bomFormat": "CycloneDX",
                "specVersion": "1.4"
            }`),
			expected: sbomFormatSPDX,
		},
		{
			name: "case sensitive field names",
			data: []byte(`{
                "spdxversion": "SPDX-2.3",
                "spdxid": "SPDXRef-DOCUMENT"
            }`),
			expected: sbomFormatUnknown,
		},
		{
			name: "case sensitive bomFormat value",
			data: []byte(`{
                "bomFormat": "cyclonedx"
            }`),
			expected: sbomFormatUnknown,
		},
		{
			name: "deeply nested JSON structure",
			data: []byte(`{
                "wrapper": {
                    "spdxVersion": "SPDX-2.3",
                    "SPDXID": "SPDXRef-DOCUMENT"
                }
            }`),
			expected: sbomFormatUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectSBOMFormat(tt.data)
			assert.Equal(t, tt.expected, result,
				"Expected SBOM format %v, got %v for input: %s",
				tt.expected, result, string(tt.data))
		})
	}
}

func TestDetectSBOMFormat_EdgeCases(t *testing.T) {
	t.Run("very large JSON", func(t *testing.T) {
		largeJSON := `{
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "large-document",
            "largeField": "`
		for i := 0; i < 10000; i++ {
			largeJSON += "x"
		}
		largeJSON += `"}`
		result := detectSBOMFormat([]byte(largeJSON))
		assert.Equal(t, sbomFormatSPDX, result)
	})

	t.Run("unicode characters", func(t *testing.T) {
		data := []byte(`{
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "测试文档",
            "description": "文档描述 with émojis 🚀"
        }`)
		assert.Equal(t, sbomFormatSPDX, detectSBOMFormat(data))
	})

	t.Run("scientific notation in JSON", func(t *testing.T) {
		data := []byte(`{
            "bomFormat": "CycloneDX",
            "version": 1e0,
            "timestamp": 1.672531200e9
        }`)
		assert.Equal(t, sbomFormatCycloneDX, detectSBOMFormat(data))
	})
}

func TestDetectSBOMFormat_ThreadSafety(t *testing.T) {
	spdxData := []byte(`{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}`)
	cdxData := []byte(`{"bomFormat": "CycloneDX"}`)

	const numGoroutines = 100
	results := make(chan sbomFormat, numGoroutines*2)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			results <- detectSBOMFormat(spdxData)
			results <- detectSBOMFormat(cdxData)
		}()
	}

	spdxCount, cdxCount := 0, 0
	for i := 0; i < numGoroutines*2; i++ {
		switch <-results {
		case sbomFormatSPDX:
			spdxCount++
		case sbomFormatCycloneDX:
			cdxCount++
		}
	}

	assert.Equal(t, numGoroutines, spdxCount)
	assert.Equal(t, numGoroutines, cdxCount)
}

func TestDetectFileType(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected fileType
	}{
		{name: "valid JSON object", data: []byte(`{"name": "test"}`), expected: fileTypeJSON},
		{name: "valid JSON array", data: []byte(`[{"name": "item"}]`), expected: fileTypeJSON},
		{name: "simple JSON string", data: []byte(`"hello"`), expected: fileTypeJSON},
		{name: "JSON number", data: []byte(`42`), expected: fileTypeJSON},
		{name: "JSON boolean", data: []byte(`true`), expected: fileTypeJSON},
		{name: "JSON null", data: []byte(`null`), expected: fileTypeJSON},
		{name: "empty JSON object", data: []byte(`{}`), expected: fileTypeJSON},
		{name: "simple XML", data: []byte(`<root><item>v</item></root>`), expected: fileTypeXML},
		{
			name:     "XML with declaration",
			data:     []byte(`<?xml version="1.0"?><root></root>`),
			expected: fileTypeXML,
		},
		{name: "empty data", data: []byte(``), expected: fileTypeUnknown},
		{name: "binary data", data: []byte{0x89, 0x50, 0x4E, 0x47}, expected: fileTypeUnknown},
		{name: "invalid XML-like", data: []byte(`<This isn't>`), expected: fileTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, detectFileType(tt.data))
		})
	}
}

func TestDetectFileType_ThreadSafety(t *testing.T) {
	jsonData := []byte(`{"test": "value"}`)
	xmlData := []byte(`<root><test>value</test></root>`)

	const numGoroutines = 100
	results := make(chan fileType, numGoroutines*2)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			results <- detectFileType(jsonData)
			results <- detectFileType(xmlData)
		}()
	}

	jsonCount, xmlCount := 0, 0
	for i := 0; i < numGoroutines*2; i++ {
		switch <-results {
		case fileTypeJSON:
			jsonCount++
		case fileTypeXML:
			xmlCount++
		}
	}

	assert.Equal(t, numGoroutines, jsonCount)
	assert.Equal(t, numGoroutines, xmlCount)
}

func TestCompareSpecVersions(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected int
	}{
		{"equal", "1.6", "1.6", 0},
		{"minor less", "1.5", "1.6", -1},
		{"minor greater", "1.7", "1.6", 1},
		// Regression: lexicographic compare would wrongly report "1.10" < "1.6".
		{"double digit minor greater", "1.10", "1.6", 1},
		{"double digit minor vs double digit", "1.10", "1.11", -1},
		{"major greater", "2.0", "1.6", 1},
		{"major less", "1.9", "2.0", -1},
		{"missing minor treated as zero", "2", "2.0", 0},
		{"unparseable treated as zero", "abc", "1.6", -1},
		{"partially unparseable", "1.x", "1.0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, compareSpecVersions(tt.a, tt.b))
		})
	}
}

func TestDowngradeCDXSpecVersion(t *testing.T) {
	extract := func(data []byte) string {
		var generic map[string]json.RawMessage
		if err := json.Unmarshal(data, &generic); err != nil {
			return ""
		}
		var v string
		_ = json.Unmarshal(generic[keySpecVersion], &v)
		return v
	}

	t.Run("newer double-digit spec is downgraded", func(t *testing.T) {
		// Regression: "1.10" is newer than "1.7" and must be downgraded.
		data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.10"}`)
		out := downgradeCDXSpecVersion(data)
		assert.Equal(t, "1.7", extract(out))
	})

	t.Run("1.6 input is unchanged", func(t *testing.T) {
		data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
		assert.Equal(t, data, downgradeCDXSpecVersion(data))
	})

	t.Run("older spec is unchanged", func(t *testing.T) {
		data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4"}`)
		assert.Equal(t, data, downgradeCDXSpecVersion(data))
	})

	t.Run("unparseable version is left untouched", func(t *testing.T) {
		data := []byte(`{"bomFormat":"CycloneDX","specVersion":"abc"}`)
		out := downgradeCDXSpecVersion(data)
		assert.Equal(t, "abc", extract(out))
	})

	t.Run("missing version returns data unchanged", func(t *testing.T) {
		data := []byte(`{"bomFormat":"CycloneDX"}`)
		out := downgradeCDXSpecVersion(data)
		assert.Equal(t, data, out)
	})
}

func TestCycloneDX17ImportInput(t *testing.T) {
	path := "testdata/cyclonedx-1.7.cdx.json"
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	input := downgradeCDXSpecVersion(raw)
	require.Equal(t, raw, input, "native 1.7 input must reach the decoder and scanner unchanged")

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(input), cdx.BOMFileFormatJSON)
	require.NoError(t, decoder.Decode(&bom))
	require.Equal(t, cdx.SpecVersion1_7, bom.SpecVersion)
	require.NotNil(t, bom.Citations)
	require.Len(t, *bom.Citations, 1)
	citation := (*bom.Citations)[0]
	require.NotNil(t, citation.AttributedTo)
	assert.Equal(t, "fixture-app", string(*citation.AttributedTo))

	inventory, err := (&scancdx.Extractor{}).Extract(context.Background(), &filesystem.ScanInput{
		Path:   path,
		Reader: bytes.NewReader(input),
	})
	require.NoError(t, err)
	var packages []string
	for _, pkg := range inventory.Packages {
		packages = append(packages, pkg.PURLType+"/"+pkg.Name+"@"+pkg.Version)
	}
	assert.ElementsMatch(t, []string{"npm/lodash@4.17.20", "npm/minimist@1.2.5"}, packages)
}

func TestCycloneDX17PreviewRejectsMalformedComponents(t *testing.T) {
	service := NewService(nil, nil)
	_, _, _, err := service.Preview([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","components":{}}`))
	require.ErrorIs(t, err, ErrCycloneDXParseFailed)
}
