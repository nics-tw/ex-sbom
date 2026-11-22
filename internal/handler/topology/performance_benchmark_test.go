// SPDX-License-Identifier: MIT

//go:build unit

package topology_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"ex-sbom/internal/handler/middleware"
	"ex-sbom/internal/handler/topology"
	ssbom "ex-sbom/internal/service/sbom"
	"ex-sbom/tests/perf"

	"github.com/gin-gonic/gin"
)

func BenchmarkTopology(b *testing.B) {
	gin.SetMode(gin.TestMode)
	for _, shape := range []perf.Shape{
		{Components: 100, Fanout: 2},
		{Components: 1000, Fanout: 3},
		{Components: 5000, Fanout: 4},
	} {
		b.Run(fmt.Sprintf("c%d-e%d", shape.Components, shape.Fanout), func(b *testing.B) {
			cache := ssbom.NewInMemoryCache()
			version := perf.Version(0)
			cache.Set(1, version, perf.BOM(0, 0, shape))
			handler := topology.New(ssbom.NewService(nil, cache))
			router := gin.New()
			group := router.Group("/projects/:id/sboms/:name/topology", middleware.ProjectID())
			group.GET("", handler.ListComponents)
			group.GET("/relations", handler.GetRelations)
			for _, operation := range []struct{ name, suffix string }{{"summary", ""}, {"relations", "/relations"}} {
				b.Run(operation.name, func(b *testing.B) {
					request := httptest.NewRequest(http.MethodGet, "/projects/1/sboms/"+version+"/topology"+operation.suffix, nil)
					b.ReportAllocs()
					for b.Loop() {
						response := httptest.NewRecorder()
						router.ServeHTTP(response, request)
						if response.Code != http.StatusOK || response.Body.Len() == 0 {
							b.Fatalf("benchmark topology failed: %d", response.Code)
						}
					}
				})
			}
		})
	}
}
