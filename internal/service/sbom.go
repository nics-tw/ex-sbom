package service

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type (
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

func ProcessCDX(name string, bom cdx.BOM) error {
	if bom.BOMFormat != cdx.BOMFormat {
		return fmt.Errorf("invalid BOM format: %s", bom.BOMFormat)
	}

	if _, ok := SBOMs[name]; ok {
		// reset the sbom
		SBOMs[name] = FormattedSBOM{}
	}

	var components []string

	if bom.Components != nil {
		for _, c := range *bom.Components {
			components = append(components, c.Name)
		}
	}

	// TODO: implement dependency level calculation

	dependency := make(map[string][]string)

	if bom.Dependencies != nil {
		for _, d := range *bom.Dependencies {
			if d.Dependencies != nil && len(*d.Dependencies) > 0 {
				dependency[d.Ref] = append(dependency[d.Ref], *d.Dependencies...)
			}
		}
	}

	SBOMs[name] = FormattedSBOM{
		Components: components,
		Dependency: dependency,
		ReverseDependency: CreateReverseDep(dependency),
	}

	return nil
}

func DeleteSBOM(name string) {
	delete(SBOMs, name)
}

func CreateReverseDep(Dependency map[string][]string) (map[string][]string) {
	// TODO: calculate non-root package number for pre-allocate the slice
	reverseDependency := make(map[string][]string)

	for k, v := range Dependency {
		for _, dep := range v {
			if _, ok := reverseDependency[dep]; !ok {
				reverseDependency[dep] = []string{}
			}
			reverseDependency[dep] = append(reverseDependency[dep], k)
		}
	}

	return reverseDependency
}
