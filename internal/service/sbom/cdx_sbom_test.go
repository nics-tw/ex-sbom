//go:build unit

package ssbom

import (
	"sort"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestGetCdxDep(t *testing.T) {
	tests := []struct {
		name      string
		input     *[]cdx.Dependency
		refToName map[string]string
		expected  map[string][]string
	}{
		{
			name:      "nil input",
			input:     nil,
			refToName: map[string]string{},
			expected:  map[string][]string{},
		},
		{
			name:      "empty dependencies",
			input:     &[]cdx.Dependency{},
			refToName: map[string]string{},
			expected:  map[string][]string{},
		},
		{
			name: "dependency with no sub-dependencies",
			input: &[]cdx.Dependency{
				{
					Ref:          "component-a",
					Dependencies: nil,
				},
				{
					Ref:          "component-b",
					Dependencies: &[]string{},
				},
			},
			refToName: map[string]string{
				"component-a": "package-a",
				"component-b": "package-b",
			},
			expected: map[string][]string{},
		},
		{
			name: "simple dependencies",
			input: &[]cdx.Dependency{
				{
					Ref: "component-a",
					Dependencies: &[]string{
						"component-b",
						"component-c",
					},
				},
			},
			refToName: map[string]string{
				"component-a": "package-a",
				"component-b": "package-b",
				"component-c": "package-c",
			},
			expected: map[string][]string{
				"package-a": {"package-b", "package-c"},
			},
		},
		{
			name: "multiple component dependencies",
			input: &[]cdx.Dependency{
				{
					Ref: "component-a",
					Dependencies: &[]string{
						"component-b",
						"component-c",
					},
				},
				{
					Ref: "component-b",
					Dependencies: &[]string{
						"component-d",
					},
				},
				{
					Ref: "component-c",
					Dependencies: &[]string{
						"component-e",
						"component-f",
					},
				},
			},
			refToName: map[string]string{
				"component-a": "package-a",
				"component-b": "package-b",
				"component-c": "package-c",
				"component-d": "package-d",
				"component-e": "package-e",
				"component-f": "package-f",
			},
			expected: map[string][]string{
				"package-a": {"package-b", "package-c"},
				"package-b": {"package-d"},
				"package-c": {"package-e", "package-f"},
			},
		},
		{
			name: "missing ref in refToName",
			input: &[]cdx.Dependency{
				{
					Ref: "component-a",
					Dependencies: &[]string{
						"component-b",
					},
				},
				{
					Ref: "missing-ref",
					Dependencies: &[]string{
						"component-c",
					},
				},
			},
			refToName: map[string]string{
				"component-a": "package-a",
				"component-b": "package-b",
				"component-c": "package-c",
			},
			expected: map[string][]string{
				"package-a": {"package-b"},
				// missing-ref should be skipped
			},
		},
		{
			name: "missing dependency in refToName",
			input: &[]cdx.Dependency{
				{
					Ref: "component-a",
					Dependencies: &[]string{
						"component-b",
						"missing-dep",
					},
				},
			},
			refToName: map[string]string{
				"component-a": "package-a",
				"component-b": "package-b",
			},
			expected: map[string][]string{
				"package-a": {"package-b"},
				// missing-dep should be skipped
			},
		},
		{
			name: "mixed case with valid and invalid references",
			input: &[]cdx.Dependency{
				{
					Ref: "component-a",
					Dependencies: &[]string{
						"component-b",
						"missing-dep-1",
					},
				},
				{
					Ref: "missing-ref",
					Dependencies: &[]string{
						"component-c",
					},
				},
				{
					Ref: "component-c",
					Dependencies: &[]string{
						"component-d",
						"missing-dep-2",
					},
				},
				{
					Ref:          "component-d",
					Dependencies: &[]string{},
				},
			},
			refToName: map[string]string{
				"component-a": "package-a",
				"component-b": "package-b",
				"component-c": "package-c",
				"component-d": "package-d",
			},
			expected: map[string][]string{
				"package-a": {"package-b"},
				"package-c": {"package-d"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCdxDep(tt.input, tt.refToName)

			// Check if result has the expected number of entries
			assert.Equal(t, len(tt.expected), len(result),
				"Result should have %d entries, got %d", len(tt.expected), len(result))

			// Check each key and its values
			for compName, expectedDeps := range tt.expected {
				resultDeps, exists := result[compName]
				assert.True(t, exists, "Component %s should exist in the result", compName)

				if exists {
					// Sort both slices for consistent comparison
					sort.Strings(expectedDeps)
					sort.Strings(resultDeps)

					assert.Equal(t, expectedDeps, resultDeps,
						"For component %s, expected dependencies %v, got %v",
						compName, expectedDeps, resultDeps)
				}
			}

			// Check that no extra components exist in the result
			for compName := range result {
				_, exists := tt.expected[compName]
				assert.True(t, exists, "Unexpected component %s in result", compName)
			}
		})
	}
}

func TestGetCdxBomRefToName(t *testing.T) {
	tests := []struct {
		name     string
		input    *[]cdx.Component
		expected map[string]string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: map[string]string{},
		},
		{
			name:     "empty component list",
			input:    &[]cdx.Component{},
			expected: map[string]string{},
		},
		{
			name: "components with empty BOMRefs",
			input: &[]cdx.Component{
				{
					BOMRef: "",
					Name:   "component-a",
				},
				{
					BOMRef: "",
					Name:   "component-b",
				},
			},
			expected: map[string]string{}, // Empty BOMRefs should be skipped
		},
		{
			name: "components with valid BOMRefs",
			input: &[]cdx.Component{
				{
					BOMRef: "ref-1",
					Name:   "component-a",
				},
				{
					BOMRef: "ref-2",
					Name:   "component-b",
				},
				{
					BOMRef: "ref-3",
					Name:   "component-c",
				},
			},
			expected: map[string]string{
				"ref-1": "component-a",
				"ref-2": "component-b",
				"ref-3": "component-c",
			},
		},
		{
			name: "mixed components with valid and empty BOMRefs",
			input: &[]cdx.Component{
				{
					BOMRef: "ref-1",
					Name:   "component-a",
				},
				{
					BOMRef: "",
					Name:   "component-b", // Should be skipped
				},
				{
					BOMRef: "ref-3",
					Name:   "component-c",
				},
			},
			expected: map[string]string{
				"ref-1": "component-a",
				"ref-3": "component-c",
			},
		},
		{
			name: "duplicate BOMRefs with different names",
			input: &[]cdx.Component{
				{
					BOMRef: "ref-1",
					Name:   "component-a",
				},
				{
					BOMRef: "ref-1", // Duplicate BOMRef
					Name:   "component-b",
				},
			},
			expected: map[string]string{
				"ref-1": "component-b", // Last one wins
			},
		},
		{
			name: "components with same name but different BOMRefs",
			input: &[]cdx.Component{
				{
					BOMRef: "ref-1",
					Name:   "component-a",
				},
				{
					BOMRef: "ref-2",
					Name:   "component-a", // Same name, different ref
				},
			},
			expected: map[string]string{
				"ref-1": "component-a",
				"ref-2": "component-a",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCdxBomRefToName(tt.input)

			// Check if result has the expected size
			assert.Equal(t, len(tt.expected), len(result),
				"Expected map size %d, got %d", len(tt.expected), len(result))

			// Check each key-value pair
			for ref, expectedName := range tt.expected {
				name, exists := result[ref]
				assert.True(t, exists, "Expected BOMRef %s not found in result", ref)
				assert.Equal(t, expectedName, name,
					"For BOMRef %s, expected name %s, got %s", ref, expectedName, name)
			}

			// Check that no extra keys exist in the result
			for ref := range result {
				_, exists := tt.expected[ref]
				assert.True(t, exists, "Unexpected BOMRef %s found in result", ref)
			}
		})
	}
}

func TestGetCdxBomRef(t *testing.T) {
	tests := []struct {
		name     string
		input    *[]cdx.Component
		expected []string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: []string{},
		},
		{
			name:     "empty component list",
			input:    &[]cdx.Component{},
			expected: []string{},
		},
		{
			name: "components with empty BOMRefs",
			input: &[]cdx.Component{
				{
					BOMRef: "",
					Name:   "component-a",
				},
				{
					BOMRef: "",
					Name:   "component-b",
				},
			},
			expected: []string{}, // Empty BOMRefs should be skipped
		},
		{
			name: "components with valid BOMRefs",
			input: &[]cdx.Component{
				{
					BOMRef: "ref-1",
					Name:   "component-a",
				},
				{
					BOMRef: "ref-2",
					Name:   "component-b",
				},
				{
					BOMRef: "ref-3",
					Name:   "component-c",
				},
			},
			expected: []string{"ref-1", "ref-2", "ref-3"},
		},
		{
			name: "mixed components with valid and empty BOMRefs",
			input: &[]cdx.Component{
				{
					BOMRef: "ref-1",
					Name:   "component-a",
				},
				{
					BOMRef: "",
					Name:   "component-b", // Should be skipped
				},
				{
					BOMRef: "ref-3",
					Name:   "component-c",
				},
			},
			expected: []string{"ref-1", "ref-3"},
		},
		{
			name: "components with duplicate BOMRefs",
			input: &[]cdx.Component{
				{
					BOMRef: "ref-1",
					Name:   "component-a",
				},
				{
					BOMRef: "ref-2",
					Name:   "component-b",
				},
				{
					BOMRef: "ref-1", // Duplicate, should be deduplicated
					Name:   "component-c",
				},
			},
			expected: []string{"ref-1", "ref-2"}, // unique.StringSlice should deduplicate
		},
		{
			name: "complex mix of valid, empty, and duplicate BOMRefs",
			input: &[]cdx.Component{
				{
					BOMRef: "ref-1",
					Name:   "component-a",
				},
				{
					BOMRef: "",
					Name:   "component-b", // Should be skipped
				},
				{
					BOMRef: "ref-2",
					Name:   "component-c",
				},
				{
					BOMRef: "ref-1", // Duplicate, should be deduplicated
					Name:   "component-d",
				},
				{
					BOMRef: "",
					Name:   "component-e", // Should be skipped
				},
				{
					BOMRef: "ref-3",
					Name:   "component-f",
				},
			},
			expected: []string{"ref-1", "ref-2", "ref-3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCdxBomRef(tt.input)

			// Check if the result has the expected length
			assert.Equal(t, len(tt.expected), len(result),
				"Expected %d BOMRefs, got %d", len(tt.expected), len(result))

			// Check if each expected BOMRef is in the result
			// Sort both slices for deterministic comparison
			sort.Strings(result)
			sort.Strings(tt.expected)

			assert.Equal(t, tt.expected, result,
				"Expected BOMRefs %v, got %v", tt.expected, result)
		})
	}
}

func TestGetCdxComponents(t *testing.T) {
	tests := []struct {
		name     string
		input    *[]cdx.Component
		expected []string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: []string{},
		},
		{
			name:     "empty slice input",
			input:    &[]cdx.Component{},
			expected: []string{},
		},
		{
			name: "unique component names",
			input: &[]cdx.Component{
				{
					Name: "component-a",
				},
				{
					Name: "component-b",
				},
				{
					Name: "component-c",
				},
			},
			expected: []string{"component-a", "component-b", "component-c"},
		},
		{
			name: "duplicate component names",
			input: &[]cdx.Component{
				{
					Name: "component-a",
				},
				{
					Name: "component-b",
				},
				{
					Name: "component-a", // Duplicate
				},
			},
			expected: []string{"component-a", "component-b"}, // Should be deduplicated
		},
		{
			name: "empty component names",
			input: &[]cdx.Component{
				{
					Name: "",
				},
				{
					Name: "component-b",
				},
				{
					Name: "", // Duplicate empty name
				},
			},
			expected: []string{"", "component-b"}, // Empty names should be included but deduplicated
		},
		{
			name: "mixed case",
			input: &[]cdx.Component{
				{
					Name: "component-a",
				},
				{
					Name: "",
				},
				{
					Name: "component-b",
				},
				{
					Name: "component-a", // Duplicate
				},
				{
					Name: "", // Duplicate empty name
				},
				{
					Name: "component-c",
				},
			},
			expected: []string{"", "component-a", "component-b", "component-c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCdxComponents(tt.input)

			// Sort both slices for deterministic comparison
			sort.Strings(result)
			sort.Strings(tt.expected)

			assert.Equal(t, tt.expected, result,
				"Expected components %v, got %v", tt.expected, result)
		})
	}
}

func TestGetCdxDependencyDepthMap(t *testing.T) {
	tests := []struct {
		name          string
		sbom          cdx.BOM
		allComponents []string
		refToName     map[string]string
		expected      map[int][]string
	}{

		{
			name: "empty dependencies",
			sbom: cdx.BOM{
				Dependencies: &[]cdx.Dependency{},
			},
			allComponents: []string{"comp-a", "comp-b"},
			refToName: map[string]string{
				"comp-a": "package-a",
				"comp-b": "package-b",
			},
			expected: map[int][]string{
				0: {"package-a", "package-b"}, // All should be at level 0 since no deps
			},
		},
		{
			name: "nil dependencies",
			sbom: cdx.BOM{
				Dependencies: nil,
			},
			allComponents: []string{"comp-a", "comp-b"},
			refToName: map[string]string{
				"comp-a": "package-a",
				"comp-b": "package-b",
			},
			expected: map[int][]string{
				0: {"package-a", "package-b"}, // All should be at level 0 since no deps
			},
		},
		{
			name: "simple linear dependency",
			sbom: cdx.BOM{
				Dependencies: &[]cdx.Dependency{
					{
						Ref:          "comp-a",
						Dependencies: &[]string{"comp-b"},
					},
					{
						Ref:          "comp-b",
						Dependencies: &[]string{"comp-c"},
					},
					{
						Ref:          "comp-c",
						Dependencies: &[]string{},
					},
				},
			},
			allComponents: []string{"comp-a", "comp-b", "comp-c"},
			refToName: map[string]string{
				"comp-a": "package-a",
				"comp-b": "package-b",
				"comp-c": "package-c",
			},
			expected: map[int][]string{
				0: {"package-a"},
				1: {"package-b"},
				2: {"package-c"},
			},
		},
		{
			name: "multiple roots and branches",
			sbom: cdx.BOM{
				Dependencies: &[]cdx.Dependency{
					{
						Ref:          "comp-a",
						Dependencies: &[]string{"comp-c", "comp-d"},
					},
					{
						Ref:          "comp-b",
						Dependencies: &[]string{"comp-e"},
					},
					{
						Ref:          "comp-c",
						Dependencies: &[]string{},
					},
					{
						Ref:          "comp-d",
						Dependencies: &[]string{"comp-f"},
					},
					{
						Ref:          "comp-e",
						Dependencies: &[]string{},
					},
					{
						Ref:          "comp-f",
						Dependencies: &[]string{},
					},
				},
			},
			allComponents: []string{"comp-a", "comp-b", "comp-c", "comp-d", "comp-e", "comp-f"},
			refToName: map[string]string{
				"comp-a": "package-a",
				"comp-b": "package-b",
				"comp-c": "package-c",
				"comp-d": "package-d",
				"comp-e": "package-e",
				"comp-f": "package-f",
			},
			expected: map[int][]string{
				0: {"package-a", "package-b"},
				1: {"package-c", "package-d", "package-e"},
				2: {"package-f"},
			},
		},
		{
			name: "diamond dependency",
			sbom: cdx.BOM{
				Dependencies: &[]cdx.Dependency{
					{
						Ref:          "comp-a",
						Dependencies: &[]string{"comp-b", "comp-c"},
					},
					{
						Ref:          "comp-b",
						Dependencies: &[]string{"comp-d"},
					},
					{
						Ref:          "comp-c",
						Dependencies: &[]string{"comp-d"},
					},
					{
						Ref:          "comp-d",
						Dependencies: &[]string{},
					},
				},
			},
			allComponents: []string{"comp-a", "comp-b", "comp-c", "comp-d"},
			refToName: map[string]string{
				"comp-a": "package-a",
				"comp-b": "package-b",
				"comp-c": "package-c",
				"comp-d": "package-d",
			},
			expected: map[int][]string{
				0: {"package-a"},
				1: {"package-b", "package-c"},
				2: {"package-d"},
			},
		},
		{
			name: "missing references in refToName",
			sbom: cdx.BOM{
				Dependencies: &[]cdx.Dependency{
					{
						Ref:          "comp-a",
						Dependencies: &[]string{"comp-b", "missing-ref"},
					},
					{
						Ref:          "comp-b",
						Dependencies: &[]string{"comp-c"},
					},
					{
						Ref:          "comp-c",
						Dependencies: &[]string{},
					},
				},
			},
			allComponents: []string{"comp-a", "comp-b", "comp-c"},
			refToName: map[string]string{
				"comp-a": "package-a",
				"comp-b": "package-b",
				"comp-c": "package-c",
				// missing-ref is intentionally missing from refToName
			},
			expected: map[int][]string{
				0: {"package-a"},
				1: {"package-b"},
				2: {"package-c"},
				// missing-ref should be skipped in the output due to missing refToName mapping
			},
		},
		{
			name: "components not in dependency graph",
			sbom: cdx.BOM{
				Dependencies: &[]cdx.Dependency{
					{
						Ref:          "comp-a",
						Dependencies: &[]string{"comp-b"},
					},
				},
			},
			allComponents: []string{"comp-a", "comp-b", "comp-isolated"}, // comp-isolated not in dependencies
			refToName: map[string]string{
				"comp-a":        "package-a",
				"comp-b":        "package-b",
				"comp-isolated": "package-isolated",
			},
			expected: map[int][]string{
				0: {"package-a", "package-isolated"}, // Both root and isolated components at level 0
				1: {"package-b"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCdxDependencyDepthMap(tt.sbom, tt.allComponents, tt.refToName)

			// Check if result has expected number of levels
			assert.Equal(t, len(tt.expected), len(result),
				"Expected %d levels, got %d", len(tt.expected), len(result))

			// Check components at each level
			for level, expectedComponents := range tt.expected {
				resultComponents, exists := result[level]
				assert.True(t, exists, "Expected level %d not found in result", level)

				if exists {
					// Sort for deterministic comparison
					sort.Strings(expectedComponents)
					sort.Strings(resultComponents)

					assert.ElementsMatch(t, expectedComponents, resultComponents,
						"For level %d, expected components %v, got %v",
						level, expectedComponents, resultComponents)
				}
			}

			// Check that no extra levels exist in result
			for level := range result {
				_, exists := tt.expected[level]
				assert.True(t, exists, "Unexpected level %d found in result", level)
			}
		})
	}
}
