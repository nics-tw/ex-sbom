//go:build unit

package ssbom

import (
	"sort"
	"testing"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/stretchr/testify/assert"
)

func TestGetRefIDStr(t *testing.T) {
	tests := []struct {
		name  string
		input common.DocElementID
		want  string
	}{
		{
			name: "should return DocumentRefID if present",
			input: common.DocElementID{
				DocumentRefID: "doc-1",
				ElementRefID:  "elem-1",
				SpecialID:     "special-1",
			},
			want: "doc-1",
		},
		{
			name: "should return ElementRefID if DocumentRefID empty",
			input: common.DocElementID{
				DocumentRefID: "",
				ElementRefID:  "elem-1",
				SpecialID:     "special-1",
			},
			want: "elem-1",
		},
		{
			name: "should return SpecialID if others empty",
			input: common.DocElementID{
				DocumentRefID: "",
				ElementRefID:  "",
				SpecialID:     "special-1",
			},
			want: "special-1",
		},
		{
			name: "should return empty string if all empty",
			input: common.DocElementID{
				DocumentRefID: "",
				ElementRefID:  "",
				SpecialID:     "",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getRefIDStr(tt.input)
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("getRefIDStr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrimSPDXPrefix(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "should trim SPDXRef prefix",
			input: "SPDXRef-component",
			want:  "component",
		},
		{
			name:  "should trim DocumentRef prefix",
			input: "DocumentRef-doc",
			want:  "doc",
		},
		{
			name:  "should return original string if no prefix",
			input: "regular-component",
			want:  "regular-component",
		},
		{
			name:  "should return empty string for empty input",
			input: "",
			want:  "",
		},
		{
			name:  "should handle case with both prefixes",
			input: "SPDXRef-DocumentRef-test",
			want:  "DocumentRef-test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimSPDXPrefix(tt.input)
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("trimSPDXPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsGeneratedRoot(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "should return true for DOCUMENT",
			input: "DOCUMENT",
			want:  true,
		},
		{
			name:  "should return true for DocumentRoot prefix",
			input: "DocumentRoot-test",
			want:  true,
		},
		{
			name:  "should return true for File prefix",
			input: "File-test",
			want:  true,
		},
		{
			name:  "should return false for regular component ID",
			input: "component-1",
			want:  false,
		},
		{
			name:  "should return false for empty string",
			input: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGeneratedRoot(tt.input)
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("isGeneratedRoot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetSpdxDep(t *testing.T) {
	tests := []struct {
		name     string
		document spdx.Document
		nameMap  map[string]string
		expected map[string][]string
	}{
		{
			name: "empty document",
			document: spdx.Document{
				Relationships: []*spdx.Relationship{},
			},
			nameMap:  map[string]string{},
			expected: map[string][]string{},
		},
		{
			name: "simple dependencies",
			document: spdx.Document{
				Relationships: []*spdx.Relationship{
					{
						RefA: common.DocElementID{ElementRefID: "SPDXRef-pkg1"},
						RefB: common.DocElementID{ElementRefID: "SPDXRef-pkg2"},
					},
					{
						RefA: common.DocElementID{ElementRefID: "SPDXRef-pkg1"},
						RefB: common.DocElementID{ElementRefID: "SPDXRef-pkg3"},
					},
				},
			},
			nameMap: map[string]string{
				"SPDXRef-pkg1": "packageA",
				"SPDXRef-pkg2": "packageB",
				"SPDXRef-pkg3": "packageC",
			},
			expected: map[string][]string{
				"packageA": {"packageB", "packageC"},
			},
		},
		{
			name: "skip generated root",
			document: spdx.Document{
				Relationships: []*spdx.Relationship{
					{
						RefA: common.DocElementID{ElementRefID: "SPDXRef-pkg1"},
						RefB: common.DocElementID{ElementRefID: "SPDXRef-pkg2"},
					},
					{
						RefA: common.DocElementID{ElementRefID: "SPDXRef-pkg1"},
						RefB: common.DocElementID{ElementRefID: "DOCUMENT"},
					},
					{
						RefA: common.DocElementID{ElementRefID: "DocumentRoot-something"},
						RefB: common.DocElementID{ElementRefID: "SPDXRef-pkg2"},
					},
				},
			},
			nameMap: map[string]string{
				"SPDXRef-pkg1":           "packageA",
				"SPDXRef-pkg2":           "packageB",
				"DOCUMENT":               "document",
				"DocumentRoot-something": "rootPkg",
			},
			expected: map[string][]string{
				"packageA": {"packageB"},
			},
		},
		{
			name: "multiple relationships",
			document: spdx.Document{
				Relationships: []*spdx.Relationship{
					{
						RefA: common.DocElementID{ElementRefID: "SPDXRef-pkg1"},
						RefB: common.DocElementID{ElementRefID: "SPDXRef-pkg2"},
					},
					{
						RefA: common.DocElementID{ElementRefID: "SPDXRef-pkg2"},
						RefB: common.DocElementID{ElementRefID: "SPDXRef-pkg3"},
					},
					{
						RefA: common.DocElementID{ElementRefID: "SPDXRef-pkg3"},
						RefB: common.DocElementID{ElementRefID: "SPDXRef-pkg4"},
					},
				},
			},
			nameMap: map[string]string{
				"SPDXRef-pkg1": "packageA",
				"SPDXRef-pkg2": "packageB",
				"SPDXRef-pkg3": "packageC",
				"SPDXRef-pkg4": "packageD",
			},
			expected: map[string][]string{
				"packageA": {"packageB"},
				"packageB": {"packageC"},
				"packageC": {"packageD"},
			},
		},
		{
			name: "missing name in map",
			document: spdx.Document{
				Relationships: []*spdx.Relationship{
					{
						RefA: common.DocElementID{ElementRefID: "SPDXRef-pkg1"},
						RefB: common.DocElementID{ElementRefID: "SPDXRef-pkg2"},
					},
					{
						RefA: common.DocElementID{ElementRefID: "SPDXRef-pkg1"},
						RefB: common.DocElementID{ElementRefID: "SPDXRef-missing"},
					},
					{
						RefA: common.DocElementID{ElementRefID: "SPDXRef-missing"},
						RefB: common.DocElementID{ElementRefID: "SPDXRef-pkg2"},
					},
				},
			},
			nameMap: map[string]string{
				"SPDXRef-pkg1": "packageA",
				"SPDXRef-pkg2": "packageB",
				// SPDXRef-missing is not in the map
			},
			expected: map[string][]string{
				"packageA": {"packageB"},
				// Relationships with missing references should be skipped
			},
		},
		{
			name: "different ID types",
			document: spdx.Document{
				Relationships: []*spdx.Relationship{
					{
						RefA: common.DocElementID{DocumentRefID: "doc1", ElementRefID: ""},
						RefB: common.DocElementID{ElementRefID: "SPDXRef-pkg1"},
					},
					{
						RefA: common.DocElementID{ElementRefID: "SPDXRef-pkg1"},
						RefB: common.DocElementID{SpecialID: "special1"},
					},
				},
			},
			nameMap: map[string]string{
				"doc1":         "document1",
				"SPDXRef-pkg1": "packageA",
				"special1":     "specialPackage",
			},
			expected: map[string][]string{
				"document1": {"packageA"},
				"packageA":  {"specialPackage"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getSpdxDep(tt.document, tt.nameMap)

			// Check if the result has the expected number of entries
			assert.Equal(t, len(tt.expected), len(result),
				"Result should have %d entries, got %d", len(tt.expected), len(result))

			// Check each key and its values
			for pkgName, deps := range tt.expected {
				resultDeps, exists := result[pkgName]
				assert.True(t, exists, "Package %s should exist in the result", pkgName)

				if exists {
					// Sort both slices for consistent comparison
					sort.Strings(deps)
					sort.Strings(resultDeps)

					assert.Equal(t, deps, resultDeps,
						"Dependencies for %s should be %v, got %v", pkgName, deps, resultDeps)
				}
			}

			// Check that no extra keys exist in the result
			for pkgName := range result {
				_, exists := tt.expected[pkgName]
				assert.True(t, exists, "Result contains unexpected package %s", pkgName)
			}
		})
	}
}
