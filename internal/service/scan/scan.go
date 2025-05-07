package sscan

import (
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

// here mimic and import the way osv-scanner/v2 scan the vulnerability
// TODO: refactor to scan directly if possible
func GetScanResult(localPath string) (models.VulnerabilityResults, error) {
	scannerAction := osvscanner.ScannerActions{
		SBOMPaths: []string{localPath},
		CallAnalysisStates: map[string]bool{
			"go":   true,
			"rust": false,
		},
	}

	return osvscanner.DoScan(scannerAction)
}
