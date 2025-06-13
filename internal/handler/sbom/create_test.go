// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package sbom

import (
	"ex-sbom/util/msg"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestDetectSBOMFormat(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected SBOMType
	}{
		{
			name: "valid SPDX SBOM",
			data: []byte(`{
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "test-document"
            }`),
			expected: SBOMSPDX,
		},
		{
			name: "SPDX with only version field",
			data: []byte(`{
                "spdxVersion": "SPDX-2.3",
                "name": "test-document"
            }`),
			expected: SBOMUnknown, // Missing SPDXID
		},
		{
			name: "SPDX with only SPDXID field",
			data: []byte(`{
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "test-document"
            }`),
			expected: SBOMUnknown, // Missing spdxVersion
		},
		{
			name: "valid CycloneDX SBOM",
			data: []byte(`{
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "version": 1
            }`),
			expected: SBOMCycloneDX,
		},
		{
			name: "CycloneDX with wrong format value",
			data: []byte(`{
                "bomFormat": "WrongFormat",
                "specVersion": "1.4",
                "version": 1
            }`),
			expected: SBOMUnknown,
		},
		{
			name: "CycloneDX with non-string format value",
			data: []byte(`{
                "bomFormat": 123,
                "specVersion": "1.4",
                "version": 1
            }`),
			expected: SBOMUnknown,
		},
		{
			name: "missing bomFormat field",
			data: []byte(`{
                "specVersion": "1.4",
                "version": 1
            }`),
			expected: SBOMUnknown,
		},
		{
			name: "invalid JSON",
			data: []byte(`{
                "bomFormat": "CycloneDX",
                "specVersion": "1.4"
                "version": 1
            }`), // Missing comma
			expected: SBOMUnknown,
		},
		{
			name:     "empty JSON object",
			data:     []byte(`{}`),
			expected: SBOMUnknown,
		},
		{
			name: "JSON array instead of object",
			data: []byte(`[
                {"bomFormat": "CycloneDX"}
            ]`),
			expected: SBOMUnknown,
		},
		{
			name:     "completely invalid JSON",
			data:     []byte(`not json at all`),
			expected: SBOMUnknown,
		},
		{
			name:     "empty data",
			data:     []byte(``),
			expected: SBOMUnknown,
		},
		{
			name:     "null JSON",
			data:     []byte(`null`),
			expected: SBOMUnknown,
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
			expected: SBOMSPDX,
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
			expected: SBOMCycloneDX,
		},
		{
			name: "both SPDX and CycloneDX fields (SPDX takes precedence)",
			data: []byte(`{
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "bomFormat": "CycloneDX",
                "specVersion": "1.4"
            }`),
			expected: SBOMSPDX, // SPDX check comes first
		},
		{
			name: "case sensitive field names",
			data: []byte(`{
                "spdxversion": "SPDX-2.3",
                "spdxid": "SPDXRef-DOCUMENT"
            }`),
			expected: SBOMUnknown, // Fields are case-sensitive
		},
		{
			name: "case sensitive bomFormat value",
			data: []byte(`{
                "bomFormat": "cyclonedx"
            }`),
			expected: SBOMUnknown, // Value is case-sensitive
		},
		{
			name: "deeply nested JSON structure",
			data: []byte(`{
                "wrapper": {
                    "spdxVersion": "SPDX-2.3",
                    "SPDXID": "SPDXRef-DOCUMENT"
                }
            }`),
			expected: SBOMUnknown, // Fields must be at root level
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectSBOMFormat(tt.data)
			assert.Equal(t, tt.expected, result,
				"Expected SBOM type %v, got %v for input: %s",
				tt.expected, result, string(tt.data))
		})
	}
}

func TestDetectSBOMFormat_EdgeCases(t *testing.T) {
	t.Run("very large JSON", func(t *testing.T) {
		// Create a large JSON with valid SPDX fields
		largeJSON := `{
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "large-document",
            "largeField": "`

		// Add a large string value
		for i := 0; i < 10000; i++ {
			largeJSON += "x"
		}
		largeJSON += `"}`

		result := detectSBOMFormat([]byte(largeJSON))
		assert.Equal(t, SBOMSPDX, result, "Should handle large JSON correctly")
	})

	t.Run("unicode characters", func(t *testing.T) {
		data := []byte(`{
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "测试文档",
            "description": "文档描述 with émojis 🚀"
        }`)

		result := detectSBOMFormat(data)
		assert.Equal(t, SBOMSPDX, result, "Should handle unicode characters")
	})

	t.Run("scientific notation in JSON", func(t *testing.T) {
		data := []byte(`{
            "bomFormat": "CycloneDX",
            "version": 1e0,
            "timestamp": 1.672531200e9
        }`)

		result := detectSBOMFormat(data)
		assert.Equal(t, SBOMCycloneDX, result, "Should handle scientific notation")
	})
}

func TestDetectSBOMFormat_ThreadSafety(t *testing.T) {
	// Test concurrent access to ensure no race conditions
	spdxData := []byte(`{
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT"
    }`)

	cdxData := []byte(`{
        "bomFormat": "CycloneDX"
    }`)

	const numGoroutines = 100
	results := make(chan SBOMType, numGoroutines*2)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			results <- detectSBOMFormat(spdxData)
			results <- detectSBOMFormat(cdxData)
		}()
	}

	spdxCount := 0
	cdxCount := 0

	for i := 0; i < numGoroutines*2; i++ {
		result := <-results
		switch result {
		case SBOMSPDX:
			spdxCount++
		case SBOMCycloneDX:
			cdxCount++
		}
	}

	assert.Equal(t, numGoroutines, spdxCount, "All SPDX detections should succeed")
	assert.Equal(t, numGoroutines, cdxCount, "All CycloneDX detections should succeed")
}

func TestDetectFileType(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected FileType
	}{
		// JSON test cases
		{
			name: "valid JSON object",
			data: []byte(`{
                "name": "test",
                "value": 123
            }`),
			expected: JSON,
		},
		{
			name: "valid JSON array",
			data: []byte(`[
                {"name": "item1"},
                {"name": "item2"}
            ]`),
			expected: JSON,
		},
		{
			name:     "simple JSON string",
			data:     []byte(`"hello world"`),
			expected: JSON,
		},
		{
			name:     "JSON number",
			data:     []byte(`42`),
			expected: JSON,
		},
		{
			name:     "JSON boolean",
			data:     []byte(`true`),
			expected: JSON,
		},
		{
			name:     "JSON null",
			data:     []byte(`null`),
			expected: JSON,
		},
		{
			name:     "empty JSON object",
			data:     []byte(`{}`),
			expected: JSON,
		},
		{
			name:     "empty JSON array",
			data:     []byte(`[]`),
			expected: JSON,
		},
		{
			name: "complex nested JSON",
			data: []byte(`{
                "users": [
                    {
                        "id": 1,
                        "profile": {
                            "name": "John",
                            "settings": {
                                "theme": "dark"
                            }
                        }
                    }
                ]
            }`),
			expected: JSON,
		},
		{
			name: "JSON with unicode",
			data: []byte(`{
                "message": "Hello 世界 🌍",
                "emoji": "🚀"
            }`),
			expected: JSON,
		},
		{
			name: "JSON with escaped characters",
			data: []byte(`{
                "text": "Line 1\nLine 2\tTabbed",
                "quote": "She said \"Hello\""
            }`),
			expected: JSON,
		},

		// XML test cases
		{
			name: "simple XML document",
			data: []byte(`<?xml version="1.0" encoding="UTF-8"?>
            <root>
                <item>value</item>
            </root>`),
			expected: XML,
		},
		{
			name: "XML without declaration",
			data: []byte(`<document>
                <title>Test Document</title>
                <content>Some content here</content>
            </document>`),
			expected: XML,
		},
		{
			name: "XML with attributes",
			data: []byte(`<book id="123" category="fiction">
                <title lang="en">Sample Book</title>
                <author>John Doe</author>
            </book>`),
			expected: XML,
		},
		{
			name: "XML with namespaces",
			data: []byte(`<?xml version="1.0"?>
            <bom xmlns="http://cyclonedx.org/schema/bom/1.4">
                <components>
                    <component type="library">
                        <name>example</name>
                    </component>
                </components>
            </bom>`),
			expected: XML,
		},
		{
			name: "XML with CDATA",
			data: []byte(`<note>
                <message><![CDATA[This is some <b>bold</b> text]]></message>
            </note>`),
			expected: XML,
		},
		{
			name: "self-closing XML tags",
			data: []byte(`<config>
                <setting name="debug" value="true" />
                <setting name="timeout" value="30" />
            </config>`),
			expected: XML,
		},

		// Unknown/Invalid test cases
		{
			name:     "empty data",
			data:     []byte(``),
			expected: Unknown,
		},
		{
			name:     "binary data",
			data:     []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, // PNG header
			expected: Unknown,
		},
		{
			name: "HTML data",
			data: []byte(`<!DOCTYPE html>
            <html>
            <head><title>Test</title></head>
            <body><h1>Hello World</h1></body>
            </html>`),
			expected: XML, // HTML is valid XML in this case
		},

		// Edge cases
		{
			name:     "XML-like text but invalid",
			data:     []byte(`<This looks like XML but isn't>`),
			expected: Unknown,
		},
		{
			name: "very large JSON",
			data: func() []byte {
				large := `{"data": "`
				for i := 0; i < 10000; i++ {
					large += "x"
				}
				large += `"}`
				return []byte(large)
			}(),
			expected: JSON,
		},
		{
			name: "JSON with scientific notation",
			data: []byte(`{
                "small": 1.23e-10,
                "large": 9.87e+15
            }`),
			expected: JSON,
		},
		{
			name: "XML with processing instructions",
			data: []byte(`<?xml version="1.0"?>
            <?xml-stylesheet type="text/xsl" href="style.xsl"?>
            <document>
                <content>Test</content>
            </document>`),
			expected: XML,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectFileType(tt.data)
			assert.Equal(t, tt.expected, result,
				"Expected file type %v, got %v for input: %s",
				tt.expected, result, string(tt.data))
		})
	}
}

func TestDetectFileType_EdgeCases(t *testing.T) {
	t.Run("concurrent access", func(t *testing.T) {
		jsonData := []byte(`{"test": "value"}`)
		xmlData := []byte(`<root><test>value</test></root>`)

		const numGoroutines = 100
		results := make(chan FileType, numGoroutines*2)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				results <- detectFileType(jsonData)
				results <- detectFileType(xmlData)
			}()
		}

		jsonCount := 0
		xmlCount := 0

		for i := 0; i < numGoroutines*2; i++ {
			result := <-results
			switch result {
			case JSON:
				jsonCount++
			case XML:
				xmlCount++
			}
		}

		assert.Equal(t, numGoroutines, jsonCount, "All JSON detections should succeed")
		assert.Equal(t, numGoroutines, xmlCount, "All XML detections should succeed")
	})

	t.Run("memory efficiency with large data", func(t *testing.T) {
		// Test that the function doesn't consume excessive memory
		largeData := make([]byte, 1024*1024) // 1MB
		for i := range largeData {
			largeData[i] = byte('a' + (i % 26))
		}

		// Prepend valid JSON structure
		jsonData := append([]byte(`{"large": "`), largeData...)
		jsonData = append(jsonData, []byte(`"}`)...)

		result := detectFileType(jsonData)
		assert.Equal(t, JSON, result, "Should handle large JSON data")
	})

	t.Run("invalid UTF-8 sequences", func(t *testing.T) {
		invalidUTF8 := []byte{0xff, 0xfe, 0xfd}
		result := detectFileType(invalidUTF8)
		assert.Equal(t, Unknown, result, "Should handle invalid UTF-8 gracefully")
	})
}

func TestDetectFileType_RealWorldExamples(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected FileType
	}{
		{
			name: "SPDX JSON example",
			data: []byte(`{
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "example-package",
                "documentNamespace": "https://example.com/spdx",
                "packages": []
            }`),
			expected: JSON,
		},
		{
			name: "CycloneDX JSON example",
			data: []byte(`{
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "version": 1,
                "components": []
            }`),
			expected: JSON,
		},
		{
			name: "CycloneDX XML example",
			data: []byte(`<?xml version="1.0" encoding="UTF-8"?>
            <bom xmlns="http://cyclonedx.org/schema/bom/1.4">
                <components>
                    <component type="library">
                        <name>example-lib</name>
                    </component>
                </components>
            </bom>`),
			expected: XML,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectFileType(tt.data)
			assert.Equal(t, tt.expected, result,
				"Expected file type %v, got %v", tt.expected, result)
		})
	}
}

func TestToCreateResponse(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedMsg  string
		expectedName string
	}{
		{
			name:         "normal filename",
			input:        "test-sbom",
			expectedMsg:  "ok",
			expectedName: "test-sbom",
		},
		{
			name:         "filename with extension",
			input:        "my-sbom.json",
			expectedMsg:  "ok",
			expectedName: "my-sbom.json",
		},
		{
			name:         "filename with path separators",
			input:        "path/to/sbom-file",
			expectedMsg:  "ok",
			expectedName: "path/to/sbom-file",
		},
		{
			name:         "filename with special characters",
			input:        "sbom_2023-12-01@v1.0",
			expectedMsg:  "ok",
			expectedName: "sbom_2023-12-01@v1.0",
		},
		{
			name:         "empty filename",
			input:        "",
			expectedMsg:  "ok",
			expectedName: "",
		},
		{
			name:         "filename with spaces",
			input:        "my sbom file",
			expectedMsg:  "ok",
			expectedName: "my sbom file",
		},
		{
			name:         "filename with unicode characters",
			input:        "测试文件名-sbom",
			expectedMsg:  "ok",
			expectedName: "测试文件名-sbom",
		},
		{
			name:         "very long filename",
			input:        "very-long-filename-that-exceeds-normal-length-expectations-for-testing-purposes",
			expectedMsg:  "ok",
			expectedName: "very-long-filename-that-exceeds-normal-length-expectations-for-testing-purposes",
		},
		{
			name:         "filename with numbers",
			input:        "sbom-123456789",
			expectedMsg:  "ok",
			expectedName: "sbom-123456789",
		},
		{
			name:         "single character filename",
			input:        "a",
			expectedMsg:  "ok",
			expectedName: "a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toCreateResponse(tt.input)

			// Verify the result is of type gin.H
			assert.IsType(t, gin.H{}, result, "Result should be of type gin.H")

			// Verify the response message
			msg, exists := result[msg.RespMsg]
			assert.True(t, exists, "Response should contain RespMsg key")
			assert.Equal(t, tt.expectedMsg, msg, "Response message should match expected")
		})
	}
}
