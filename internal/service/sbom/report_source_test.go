// SPDX-License-Identifier: MIT

//go:build unit

package ssbom

import (
	"testing"
	"time"

	"ex-sbom/util/file"

	"github.com/stretchr/testify/require"
)

func TestReportSourceDistinguishesExactQueryCoverage(t *testing.T) {
	first := file.IdentifyPackage("log", "1.0.0", "pkg:npm/%40example/log@1.0.0")
	other := file.IdentifyPackage("log", "1.0.0", "pkg:npm/%40different/log@1.0.0")
	pypi := file.IdentifyPackage("log", "1.0.0", "pkg:pypi/log@1.0.0")
	require.Equal(t, "@example/log", first.Name)
	require.NotEqual(t, first, other)
	require.NotEqual(t, first, pypi)

	observation := file.QueryObservation{CompletedAt: time.Now(), Packages: map[file.PackageVersion]struct{}{first: {}}}
	components := map[string]Component{"log": {}}
	require.Equal(t, QueryCompleted, observedSource([]file.PackageVersion{first}, components, observation).Status)
	observation.MinimumFindings = 1
	require.Equal(t, QueryPartial, observedSource([]file.PackageVersion{first}, components, observation).Status)
	observation.MinimumFindings = 0
	for _, unconfirmed := range []file.PackageVersion{other, pypi, {}} {
		source := observedSource([]file.PackageVersion{first, unconfirmed}, map[string]Component{"first": {}, "second": {}}, observation)
		require.Equal(t, QueryPartial, source.Status)
		require.Equal(t, observation.CompletedAt, *source.QueriedAt)
	}
	require.Equal(t, QueryNotRun, observedSource([]file.PackageVersion{first}, components, file.QueryObservation{}).Status)
}

func TestReportSourceDoesNotChangeAnalysisHash(t *testing.T) {
	sbom := FormattedSBOM{Components: []string{"example"}}
	legacy := HashSBOM(sbom)
	first := time.Date(2026, 11, 22, 1, 0, 0, 0, time.UTC)
	second := first.Add(time.Minute)
	sbom.ReportSource = &ReportSource{FileName: "first.json", Status: QueryCompleted, QueriedAt: &first}
	require.Equal(t, legacy, HashSBOM(sbom))
	sbom.ReportSource = &ReportSource{FileName: "second.json", Status: QueryPartial, QueriedAt: &second}
	require.Equal(t, legacy, HashSBOM(sbom))
}
