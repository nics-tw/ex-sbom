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
