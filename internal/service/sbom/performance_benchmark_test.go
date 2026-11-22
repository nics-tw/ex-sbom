// SPDX-License-Identifier: MIT

//go:build unit

package ssbom_test

import (
	"fmt"
	"testing"

	ssbom "ex-sbom/internal/service/sbom"
	"ex-sbom/tests/perf"
)

func BenchmarkSearchAndDiff(b *testing.B) {
	for _, shape := range []perf.Shape{
		{Projects: 1, Versions: 4, Components: 100, Fanout: 2},
		{Projects: 2, Versions: 8, Components: 1000, Fanout: 3},
		{Projects: 4, Versions: 16, Components: 5000, Fanout: 4},
	} {
		b.Run(fmt.Sprintf("p%d-v%d-c%d-e%d", shape.Projects, shape.Versions, shape.Components, shape.Fanout), func(b *testing.B) {
			cache := ssbom.NewInMemoryCache()
			for project := range shape.Projects {
				for version := range shape.Versions {
					cache.Set(int64(project+1), perf.Version(version), perf.BOM(project, version, shape))
				}
			}
			service := ssbom.NewService(nil, cache)
			b.Run("warm/search", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if result := service.Search(1, perf.SearchTerm); len(result) == 0 {
						b.Fatal("benchmark query returned no matches")
					}
				}
			})
			b.Run("warm/diff", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					result, err := service.Diff(1, perf.Version(0), perf.Version(1))
					if err != nil || len(result.ByLevel) == 0 {
						b.Fatalf("benchmark diff returned no changes: %v", err)
					}
				}
			})
			b.Run("warm/cache-hit", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if result, ok := cache.Get(1, perf.Version(0)); !ok || len(result.Components) != shape.Components {
						b.Fatal("benchmark lookup missed its fixture")
					}
				}
			})
		})
	}
}
