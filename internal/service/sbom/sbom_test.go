//go:build unit

package ssbom

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/google/osv-scanner/v2/pkg/models"
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
			if !assert.Equal(t, tt.expected, result) {
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
		versions [][]string // Changed from []string to [][]string
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
			name:     "has severe vuln",
			vulns:    []Vuln{{CVSSScore: "1.0"}},
			expected: false,
		},
		{
			name:     "has severe vuln with CVSS score",
			vulns:    []Vuln{{CVSSScore: "7.5"}},
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

func TestIsSevereVuln(t *testing.T) {
	tests := []struct {
		name     string
		vuln     Vuln
		expected bool
	}{
		{
			name:     "severe vuln",
			vuln:     Vuln{CVSSScore: "7.5"},
			expected: true,
		},
		{
			name:     "non-severe vuln",
			vuln:     Vuln{CVSSScore: "4.0"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSevereVuln(tt.vuln)
			if !assert.Equal(t, tt.expected, result) {
				t.Errorf("IsSevereVuln() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetAffecteds(t *testing.T) {
	tests := []struct {
		name              string
		component         string
		reverseDependency map[string][]string
		expected          []string
	}{
		{
			name:              "no dependents",
			component:         "isolated",
			reverseDependency: map[string][]string{},
			expected:          []string{},
		},
		{
			name:      "direct dependents only",
			component: "base",
			reverseDependency: map[string][]string{
				"base": {"app1", "app2"},
			},
			expected: []string{"app1", "app2"},
		},
		{
			name:      "direct and indirect dependents",
			component: "lib",
			reverseDependency: map[string][]string{
				"lib":   {"util1", "util2"},
				"util1": {"app1", "app2"},
				"util2": {"app3"},
			},
			expected: []string{"util1", "util2", "app1", "app2", "app3"},
		},
		{
			name:      "multiple dependency paths",
			component: "core",
			reverseDependency: map[string][]string{
				"core":  {"lib1", "lib2"},
				"lib1":  {"app1", "app2"},
				"lib2":  {"app2", "app3"}, // app2 depends on both lib1 and lib2
				"app3":  {"plugin1"},
				"app1":  {"plugin2"},
				"other": {"unrelated"},
			},
			expected: []string{"lib1", "lib2", "app1", "app2", "app3", "plugin1", "plugin2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getAffecteds(tt.component, tt.reverseDependency)

			// Sort both slices for deterministic comparison
			sort.Strings(result)
			sort.Strings(tt.expected)

			if !assert.ElementsMatch(t, tt.expected, result) {
				t.Errorf("getAffecteds() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetReverseDep(t *testing.T) {
    tests := []struct {
        name       string
        dependency map[string][]string
        expected   map[string][]string
    }{
        {
            name:       "empty dependency map",
            dependency: map[string][]string{},
            expected:   map[string][]string{},
        },
        {
            name: "simple dependency map",
            dependency: map[string][]string{
                "A": {"B", "C"},
            },
            expected: map[string][]string{
                "B": {"A"},
                "C": {"A"},
            },
        },
        {
            name: "complex dependency map",
            dependency: map[string][]string{
                "A": {"B", "C"},
                "B": {"D"},
                "E": {"C", "F"},
            },
            expected: map[string][]string{
                "B": {"A"},
                "C": {"A", "E"},
                "D": {"B"},
                "F": {"E"},
            },
        },
        {
            name: "component with multiple dependents",
            dependency: map[string][]string{
                "app1": {"lib1"},
                "app2": {"lib1"},
                "app3": {"lib1"},
            },
            expected: map[string][]string{
                "lib1": {"app1", "app2", "app3"},
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := getReverseDep(tt.dependency)
            
            // Check maps have same number of keys
            assert.Equal(t, len(tt.expected), len(result))
            
            // For each key, check values
            for k, expectedSlice := range tt.expected {
                resultSlice, ok := result[k]
                assert.True(t, ok, "Expected key %s not found in result", k)
                assert.ElementsMatch(t, expectedSlice, resultSlice, "Values for key %s don't match", k)
            }
        })
    }
}

func TestGetAllFixVersions(t *testing.T) {
    tests := []struct {
        name     string
        vuln     osvschema.Vulnerability
        expected []string
    }{
        {
            name:     "empty vulnerability",
            vuln:     osvschema.Vulnerability{},
            expected: []string{},
        },
        {
            name: "single fixed version",
            vuln: osvschema.Vulnerability{
                Affected: []osvschema.Affected{
                    {
                        Ranges: []osvschema.Range{
                            {
                                Events: []osvschema.Event{
                                    {Fixed: "1.2.3"},
                                },
                            },
                        },
                    },
                },
            },
            expected: []string{"1.2.3"},
        },
        {
            name: "multiple fixed versions",
            vuln: osvschema.Vulnerability{
                Affected: []osvschema.Affected{
                    {
                        Ranges: []osvschema.Range{
                            {
                                Events: []osvschema.Event{
                                    {Fixed: "1.2.3"},
                                    {Fixed: "2.0.0"},
                                },
                            },
                        },
                    },
                },
            },
            expected: []string{"1.2.3", "2.0.0"},
        },
        {
            name: "duplicate fixed versions",
            vuln: osvschema.Vulnerability{
                Affected: []osvschema.Affected{
                    {
                        Ranges: []osvschema.Range{
                            {
                                Events: []osvschema.Event{
                                    {Fixed: "1.2.3"},
                                    {Fixed: "1.2.3"}, // Duplicate
                                },
                            },
                        },
                    },
                },
            },
            expected: []string{"1.2.3"}, // Should only appear once
        },
        {
            name: "multiple affected packages with different fixed versions",
            vuln: osvschema.Vulnerability{
                Affected: []osvschema.Affected{
                    {
                        Ranges: []osvschema.Range{
                            {
                                Events: []osvschema.Event{
                                    {Fixed: "1.2.3"},
                                },
                            },
                        },
                    },
                    {
                        Ranges: []osvschema.Range{
                            {
                                Events: []osvschema.Event{
                                    {Fixed: "4.5.6"},
                                },
                            },
                        },
                    },
                },
            },
            expected: []string{"1.2.3", "4.5.6"},
        },
        {
            name: "complex nested structure",
            vuln: osvschema.Vulnerability{
                Affected: []osvschema.Affected{
                    {
                        Ranges: []osvschema.Range{
                            {
                                Events: []osvschema.Event{
                                    {Fixed: "1.2.3"},
                                },
                            },
                            {
                                Events: []osvschema.Event{
                                    {Fixed: "2.3.4"},
                                    {Fixed: ""},   // Empty fixed version
                                },
                            },
                        },
                    },
                    {
                        Ranges: []osvschema.Range{
                            {
                                Events: []osvschema.Event{
                                    {Fixed: "3.4.5"},
                                    {Fixed: "1.2.3"}, // Duplicate across packages
                                },
                            },
                        },
                    },
                },
            },
            expected: []string{"1.2.3", "2.3.4", "3.4.5"},
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := getAllFixVersions(tt.vuln)
            
            // Sort both slices for consistent comparison
            sort.Strings(result)
            sort.Strings(tt.expected)
            
            if !assert.ElementsMatch(t, tt.expected, result) {
                t.Errorf("getAllFixVersions() = %v, want %v", result, tt.expected)
            }
        })
    }
}

func TestGetVersionString(t *testing.T) {
	tests := []struct {
		name     string
		versions []string
		expected string
	}{
		{
			name:     "single version",
			versions: []string{"1.2.3"},
			expected: "1.2.3",
		},
		{
			name:     "multiple versions",
			versions: []string{"1.2.3", "2.3.4"},
			expected: "1.2.3, 2.3.4",
		},
		{
			name:     "empty versions",
			versions: []string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getVersionString(tt.versions)
			if !assert.Equal(t, tt.expected, result) {
				t.Errorf("getVersionString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetVulns(t *testing.T) {
    // Setup test data
    mockVulnMap := map[string]models.PackageVulns{
        "package1": {
            Vulnerabilities: []osvschema.Vulnerability{
                {
                    ID:      "CVE-2023-1234",
                    Summary: "Test vulnerability 1",
                    Details: "Details for test vulnerability 1",
                    Affected: []osvschema.Affected{
                        {
                            Ranges: []osvschema.Range{
                                {
                                    Events: []osvschema.Event{
                                        {Fixed: "1.2.4"},
                                        {Fixed: "2.0.0"},
                                    },
                                },
                            },
                        },
                    },
                },
            },
            Groups: []models.GroupInfo{
                {
                    IDs:         []string{"CVE-2023-1234"},
                    MaxSeverity: "7.5",
                },
            },
        },
        "package2": {
            Vulnerabilities: []osvschema.Vulnerability{
                {
                    ID:      "CVE-2023-5678",
                    Summary: "Test vulnerability 2",
                    Details: "Details for test vulnerability 2",
                    Affected: []osvschema.Affected{
                        {
                            Ranges: []osvschema.Range{
                                {
                                    Events: []osvschema.Event{
                                        {Fixed: "2.3.0"},
                                    },
                                },
                            },
                        },
                    },
                },
                {
                    ID:      "CVE-2023-9012",
                    Summary: "Test vulnerability 3",
                    Details: "Details for test vulnerability 3",
                    Affected: []osvschema.Affected{
                        {
                            Ranges: []osvschema.Range{
                                {
                                    Events: []osvschema.Event{
                                        {Fixed: "3.0.0"},
                                        {Fixed: "2.5.0"},
                                    },
                                },
                            },
                        },
                    },
                },
            },
            Groups: []models.GroupInfo{
                {
                    IDs:         []string{"CVE-2023-5678"},
                    MaxSeverity: "4.5",
                },
                {
                    IDs:         []string{"CVE-2023-9012"},
                    MaxSeverity: "8.0",
                },
            },
        },
        "package3": {
            Vulnerabilities: []osvschema.Vulnerability{},
            Groups:          []models.GroupInfo{},
        },
    }

    tests := []struct {
        name          string
        packageName   string
        packageVer    string
        expectedCount int
        checkDetails  bool
    }{
        {
            name:          "package with one vulnerability",
            packageName:   "package1",
            packageVer:    "1.2.3",
            expectedCount: 1,
            checkDetails:  true,
        },
        {
            name:          "package with multiple vulnerabilities",
            packageName:   "package2",
            packageVer:    "2.0.0",
            expectedCount: 2,
            checkDetails:  true,
        },
        {
            name:          "package with no vulnerabilities",
            packageName:   "package3",
            packageVer:    "1.0.0",
            expectedCount: 0,
            checkDetails:  false,
        },
        {
            name:          "package not in vulnerability map",
            packageName:   "nonexistent",
            packageVer:    "1.0.0",
            expectedCount: 0,
            checkDetails:  false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := getVulns(tt.packageName, tt.packageVer, mockVulnMap)
            
            // Check the length of result
            assert.Equal(t, tt.expectedCount, len(result))
            
            if tt.checkDetails {
                // Check if the result contains the expected vulnerabilities
                switch tt.packageName {
                case "package1":
                    assert.Equal(t, "CVE-2023-1234", result[0].ID)
                    assert.Equal(t, "Test vulnerability 1", result[0].Summary)
                    assert.Equal(t, "Details for test vulnerability 1", result[0].Details)
                    assert.Equal(t, "7.5", result[0].CVSSScore)
                    assert.Contains(t, result[0].FixVersions, "1.2.4")
                    assert.Contains(t, result[0].FixVersions, "2.0.0")
                    
                case "package2":
                    // Check first vulnerability
                    assert.Equal(t, "CVE-2023-5678", result[0].ID)
                    assert.Equal(t, "4.5", result[0].CVSSScore)
                    assert.Contains(t, result[0].FixVersions, "2.3.0")
                    
                    // Check second vulnerability
                    assert.Equal(t, "CVE-2023-9012", result[1].ID)
                    assert.Equal(t, "8.0", result[1].CVSSScore)
                    assert.Contains(t, result[1].FixVersions, "3.0.0")
                    assert.Contains(t, result[1].FixVersions, "2.5.0")
                    
                    // Check suggestion logic
                    if tt.packageVer == "2.0.0" {
                        assert.Equal(t, "2.3.0", result[0].SuggestFixVersion)
                        assert.Equal(t, "2.5.0, 3.0.0", result[1].SuggestFixVersion)
                    }
                }
            } else if tt.expectedCount == 0 {
                // For packages with no vulns or nonexistent packages
                assert.Nil(t, result)
            }
        })
    }
}

func TestGetVulnNumber(t *testing.T) {
    // Setup test data
    mockVulnMap := map[string]models.PackageVulns{
        "package1": {
            Vulnerabilities: []osvschema.Vulnerability{
                {ID: "CVE-2023-1111"},
                {ID: "CVE-2023-2222"},
                {ID: "CVE-2023-3333"},
            },
        },
        "package2": {
            Vulnerabilities: []osvschema.Vulnerability{
                {ID: "CVE-2023-4444"},
            },
        },
        "package3": {
            Vulnerabilities: []osvschema.Vulnerability{},
        },
    }

    tests := []struct {
        name         string
        packageName  string
        vulnMap      map[string]models.PackageVulns
        expectedVuln int
    }{
        {
            name:         "package with multiple vulnerabilities",
            packageName:  "package1",
            vulnMap:      mockVulnMap,
            expectedVuln: 3,
        },
        {
            name:         "package with single vulnerability",
            packageName:  "package2",
            vulnMap:      mockVulnMap,
            expectedVuln: 1,
        },
        {
            name:         "package with no vulnerabilities",
            packageName:  "package3",
            vulnMap:      mockVulnMap,
            expectedVuln: 0,
        },
        {
            name:         "package not in vulnerability map",
            packageName:  "nonexistent",
            vulnMap:      mockVulnMap,
            expectedVuln: 0,
        },
        {
            name:         "empty vulnerability map",
            packageName:  "package1",
            vulnMap:      map[string]models.PackageVulns{},
            expectedVuln: 0,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := getVulnNumber(tt.packageName, tt.vulnMap)
            if !assert.Equal(t, tt.expectedVuln, result) {
                t.Errorf("getVulnNumber(%s, vulnMap) = %d, want %d", 
                    tt.packageName, result, tt.expectedVuln)
            }
        })
    }
}

func TestGetCVSS(t *testing.T) {
    tests := []struct {
        name      string
        id        string
        groups    []models.GroupInfo
        expected  string
    }{
        {
            name: "ID found in single group",
            id:   "CVE-2023-1234",
            groups: []models.GroupInfo{
                {
                    IDs:         []string{"CVE-2023-1234"},
                    MaxSeverity: "7.5",
                },
            },
            expected: "7.5",
        },
        {
            name: "ID found in multiple groups",
            id:   "CVE-2023-1234",
            groups: []models.GroupInfo{
                {
                    IDs:         []string{"CVE-2023-5678"},
                    MaxSeverity: "4.5",
                },
                {
                    IDs:         []string{"CVE-2023-1234", "CVE-2023-9012"},
                    MaxSeverity: "8.0",
                },
            },
            expected: "8.0",
        },
        {
            name: "ID not found in any group",
            id:   "CVE-2023-9999",
            groups: []models.GroupInfo{
                {
                    IDs:         []string{"CVE-2023-1234"},
                    MaxSeverity: "7.5",
                },
                {
                    IDs:         []string{"CVE-2023-5678"},
                    MaxSeverity: "4.5",
                },
            },
            expected: "",
        },
        {
            name:      "Empty groups array",
            id:        "CVE-2023-1234",
            groups:    []models.GroupInfo{},
            expected:  "",
        },
        {
            name: "Empty IDs array",
            id:   "CVE-2023-1234",
            groups: []models.GroupInfo{
                {
                    IDs:         []string{},
                    MaxSeverity: "7.5",
                },
            },
            expected: "",
        },
        {
            name: "Group with nil IDs",
            id:   "CVE-2023-1234",
            groups: []models.GroupInfo{
                {
                    IDs:         nil,
                    MaxSeverity: "7.5",
                },
            },
            expected: "",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := getCVSS(tt.id, tt.groups)
            if result != tt.expected {
                t.Errorf("getCVSS(%s, groups) = %s, want %s", 
                    tt.id, result, tt.expected)
            }
        })
    }
}

func TestGetSBOM(t *testing.T) {
    // Save original value to restore later
    originalSBOMs := SBOMs
    defer func() {
        SBOMs = originalSBOMs
    }()
    
    // Setup test data
    SBOMs = map[string]FormattedSBOM{
        "existing": {
            Components: []string{"comp1", "comp2"},
            Dependency: map[string][]string{
                "comp1": {"comp2"},
            },
            ComponentInfo: map[string]Component{
                "comp1": {Name: "comp1", Version: "1.0"},
            },
        },
    }
    
    tests := []struct {
        name          string
        sbomName      string
        expectError   bool
        validateSBOM  bool
        expectedComps []string
    }{
        {
            name:          "existing SBOM",
            sbomName:      "existing",
            expectError:   false,
            validateSBOM:  true,
            expectedComps: []string{"comp1", "comp2"},
        },
        {
            name:         "non-existent SBOM",
            sbomName:     "nonexistent",
            expectError:  true,
            validateSBOM: false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := GetSBOM(tt.sbomName)
            
            if tt.expectError {
                assert.Error(t, err)
                assert.Contains(t, err.Error(), "SBOM not found")
                assert.Equal(t, FormattedSBOM{}, result)
            } else {
                assert.NoError(t, err)
                
                if tt.validateSBOM {
                    assert.Equal(t, tt.expectedComps, result.Components)
                    assert.Contains(t, result.Dependency, "comp1")
                    assert.Contains(t, result.ComponentInfo, "comp1")
                    assert.Equal(t, "1.0", result.ComponentInfo["comp1"].Version)
                }
            }
        })
    }
}
