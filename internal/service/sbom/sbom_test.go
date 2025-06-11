//go:build unit

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
		{
			name:    "prefix v in version",
			version: "v1.2.3",
			expected: version{
				Original: "1.2.3",
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

func TestGetDiff(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected []string
	}{
		{
			name:     "no changes",
			a:        []string{"1.2.3", "1.2.4"},
			b:        []string{"1.2.3", "1.2.4"},
			expected: []string{},
		},
		{
			name:     "sub have new element",
			a:        []string{"1.2.3"},
			b:        []string{"1.2.3", "1.2.4"},
			expected: []string{},
		},
		{
			name:     "objects have different elements",
			a:        []string{"1.2.3", "1.2.4"},
			b:        []string{"1.2.3"},
			expected: []string{"1.2.4"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDiff(tt.a, tt.b)
			if !assert.ElementsMatch(t, tt.expected, result) {
				t.Errorf("getDiff() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetRootComponents(t *testing.T) {
	tests := []struct {
		name     string
		allComps []string
		dep      map[int][]string
		expected []string
	}{
		{
			name:     "one root component",
			allComps: []string{"a", "b", "c", "d"},
			dep: map[int][]string{
				1: {"b", "c"},
				2: {"d"},
			},
			expected: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getRootComponents(tt.allComps, tt.dep)
			if !assert.ElementsMatch(t, tt.expected, result) {
				t.Errorf("getRootComponents() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetSuggestFixVersions(t *testing.T) {
    tests := []struct {
        name     string
        target   string
        versions [][]string  // Changed from []string to [][]string
        expected string
    }{
        {
            name:     "single array",
            target:   "1.2.3",
            versions: [][]string{{"1.2.4", "1.3.0", "2.0.0"}},
            expected: "1.2.4",
        },
        {
            name:     "trim older versions",
            target:   "1.2.3",
            versions: [][]string{{"0.2.2"}},
            expected: "",
        },
        {
            name:     "suggest breaking change version",
            target:   "1.2.3",
            versions: [][]string{{"2.0.0", "3.0.0"}},
            expected: "2.0.0",
        },
        {
            name:     "multiple version arrays",
            target:   "1.2.3",
            versions: [][]string{{"1.3.0", "1.4.0"}, {"2.0.0", "3.0.0"}},
            expected: "2.0.0", // Highest from the smallest of each array
        },
        {
            name:     "mixed version arrays with different orders",
            target:   "1.2.3",
            versions: [][]string{{"2.0.0", "1.3.0"}, {"1.2.5", "1.2.4"}},
            expected: "1.3.0", // 1.3.0 > 1.2.4
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Use unpacking operator to pass multiple slices
            result := GetSuggestFixVersions(tt.target, tt.versions...)
            if !assert.Equal(t, tt.expected, result) {
                t.Errorf("getSuggestFixVersions() = %v, want %v", result, tt.expected)
            }
        })
    }
}

func TestIsBreakingChange(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		suggest  string
		expected bool
	}{
		{
			name:     "breaking change",
			target:   "1.2.3",
			suggest:  "2.0.0",
			expected: true,
		},
		{
			name:     "not breaking change",
			target:   "1.2.3",
			suggest:  "1.2.4",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBreakingChange(tt.target, tt.suggest)
			if result != tt.expected {
				t.Errorf("IsBreakingChange(%s, %s) = %v, want %v", tt.target, tt.suggest, result, tt.expected)
			}
		})
	}
}

func TestHasSevereVuln(t *testing.T) {
	tests := []struct {
		name     string
		vulns    []Vuln
		expected bool
	}{
		{
			name: "has severe vuln",
			vulns: []Vuln{{CVSSScore: "1.0"}},
			expected: false,
		},
		{
			name: "has severe vuln with CVSS score",
			vulns: []Vuln{{CVSSScore: "7.5"}},
			expected: true,
		},
		{
			name: "multiple vulns with one severe",
			vulns: []Vuln{
				{CVSSScore: "4.0"},
				{CVSSScore: "9.0"},	
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasSevereVuln(tt.vulns)
			if !assert.Equal(t, tt.expected, result) {
				t.Errorf("HasSevereVuln() = %v, want %v", result, tt.expected)
			}
		})
	}

}
