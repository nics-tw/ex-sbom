// SPDX-License-Identifier: MIT

package ssbom

import (
	"time"

	"ex-sbom/util/file"
)

type QueryStatus string

const (
	QueryCompleted QueryStatus = "completed"
	QueryPartial   QueryStatus = "partial"
	QueryNotRun    QueryStatus = "not_run"
	QueryFailed    QueryStatus = "failed"
)

// ReportSource is server-observed provenance. It is saved with the
// snapshot and signed in the preview, independently of the result hash.
type ReportSource struct {
	FileName          string      `json:"filename,omitempty"`
	FileSHA256        string      `json:"sha256,omitempty"`
	Specification     string      `json:"specification,omitempty"`
	Status            QueryStatus `json:"query_status,omitempty"`
	QueriedAt         *time.Time  `json:"queried_at,omitempty"`
	KEVCatalogVersion string      `json:"kev_catalog_version,omitempty"`
	KEVCheckedAt      *time.Time  `json:"kev_checked_at,omitempty"`
}

func observedSource(packages []file.PackageVersion, components map[string]Component, observation file.QueryObservation) *ReportSource {
	source := &ReportSource{Status: QueryNotRun}
	if observation.CompletedAt.IsZero() {
		return source
	}

	source.Status = QueryCompleted
	source.QueriedAt = &observation.CompletedAt
	if len(packages) == 0 || len(packages) != len(components) {
		source.Status = QueryPartial
		return source
	}
	for _, pkg := range packages {
		if _, confirmed := observation.Packages[pkg]; !confirmed {
			source.Status = QueryPartial
			break
		}
	}
	// The persisted inventory is keyed by display name and can omit findings
	// the scanner observed. Such a result cannot substantiate "no findings".
	if observation.MinimumFindings > 0 {
		var stored int
		for _, component := range components {
			stored += len(component.Vulns)
		}
		if stored < observation.MinimumFindings {
			source.Status = QueryPartial
		}
	}
	return source
}
