package ssbom

import "fmt"

type (
	// FormattedSBOM is a struct that contains the formatted SBOM data, which is originally in SPDX or CycloneDX defined format.
	FormattedSBOM struct {
		Components      []string
		DependencyLevel map[int][]string
		Dependency      map[string][]string
		// Reverse dependency is designed for finding out the components that depend on a specific component
		// in this case the specific one with vuln that the CVSS score is higher than 7(or user defined)
		ReverseDependency map[string][]string
		// ComponentToLevel is an map with util designed for finding out the level of a specific component
		// in this case it is used for topology drawing
		ComponentToLevel map[string]int
	}
)

var (
	SBOMs = map[string]FormattedSBOM{}

	CVSSThreshold = int(7)
)

func GetSBOM(name string) (FormattedSBOM, error) {
	sbom, ok := SBOMs[name]
	if !ok {
		return FormattedSBOM{}, fmt.Errorf("SBOM not found")
	}
	return sbom, nil
}

func DeleteSBOM(name string) {
	delete(SBOMs, name)
}

func getComponentToLevel(DependencyLevel map[int][]string) map[string]int {
	componentToLevel := make(map[string]int)

	for level, components := range DependencyLevel {
		for _, component := range components {
			componentToLevel[component] = level
		}
	}

	return componentToLevel
}
