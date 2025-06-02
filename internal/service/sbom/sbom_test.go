package ssbom

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindNearestVersions(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		versions []string
		expected []string
	}{
		{
			name:     "in same big version and higher one",
			target:   "2.3.45",
			versions: []string{"1.2.3", "2.4.5", "4.77.8", "67.8.9"},
			expected: []string{"2.4.5", "4.77.8"},
		},
		{
			name:     "in same big version",
			target:   "2.3.45",
			versions: []string{"2.3.46", "2.4.47"},
			expected: []string{"2.3.46"},
		},
		{
			name:     "all older versions",
			target:   "2.3.45",
			versions: []string{"1.2.3"},
			expected: []string{},
		},
		{
			name:     "non-well-formatted versions",
			target:   "2.3.45-beta",
			versions: []string{"2.3.46", "2.4.47"},
			expected: []string{"2.3.46"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findNearestVersions(tt.target, tt.versions)
			if !assert.ElementsMatch(t, tt.expected, result) {
				t.Errorf("findNearestVersions() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected version
	}{
		{
			name:    "valid version",
			version: "1.2.3",
			expected: version{
				Original: "1.2.3",
				Parts:    []int{1, 2, 3},
			},
		},
		{
			name:    "valid version with postfix",
			version: "1.2.3-beta",
			expected: version{
				Original: "1.2.3-beta",
				Parts:    []int{1, 2, 3},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseVersion(tt.version)
			if !assert.Equal(t, tt.expected, result) {
				t.Errorf("parseVersion(%s) = %v, want %v", tt.version, result, tt.expected)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{
			name:     "equal versions",
			v1:       "1.2.3",
			v2:       "1.2.3",
			expected: 0,
		},
		{
			name:     "v1 is less than v2",
			v1:       "1.2.3",
			v2:       "1.2.4",
			expected: -1,
		},
		{
			name:     "v1 is greater than v2",
			v1:       "1.2.4",
			v2:       "1.2.3",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1 := parseVersion(tt.v1)
			v2 := parseVersion(tt.v2)

			result := compareVersions(v1, v2)
			if result != tt.expected {
				t.Errorf("compareVersions(%s, %s) = %d, want %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}
