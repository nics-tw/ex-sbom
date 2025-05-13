package file

import (
	"errors"
	"regexp"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

// here mimic and import the way osv-scanner/v2 scan the vulnerability
// TODO: refactor to scan directly if possible
func GetScanResult(localPath string) (map[string]models.PackageVulns, error) {
	scannerAction := osvscanner.ScannerActions{
		SBOMPaths: []string{localPath},
		CallAnalysisStates: map[string]bool{
			"go":   true,
			"rust": false,
		},
	}

	result, err := osvscanner.DoScan(scannerAction)
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		return nil, err
	}

	nameMap := make(map[string]models.PackageVulns)

	if len(result.Results) > 0 {
		for _, r := range result.Results {
			if len(r.Packages) > 0 {
				for _, pkg := range r.Packages {
					pkgName := getPackageName(pkg.Package.Name)

					if pkgName != "" {
						nameMap[pkgName] = pkg
					}
				}
			}
		}
	}

	return nameMap, nil
}

func getPackageName(input string) string {
	// the pattern is like this: `symfony/http-foundation``, and we need to extract the name `http-foundation`
	pattern := regexp.MustCompile(`(?m)\/([^\/]+)$`)
	matches := pattern.FindStringSubmatch(input)
	if len(matches) > 1 {
		return matches[1]
	}

	return input
}
