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
