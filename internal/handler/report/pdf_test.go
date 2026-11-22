//go:build unit

package report

import (
	"mime"
	"net/http"
	"net/http/httptest"
	"testing"

	"ex-sbom/internal/domain"
	"ex-sbom/internal/handler/middleware"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestReportRouteLanguageAndFilename(t *testing.T) {
	cache := ssbom.NewInMemoryCache()
	cache.Set(1, "測試版本", ssbom.FormattedSBOM{})
	h := New(ssbom.NewService(reportRepository{}, cache))
	router := gin.New()
	router.GET("/projects/:id/sboms/:name/report", middleware.ProjectID(), h.CreatePDF)

	for _, tt := range []struct{ query, language string }{
		{"", "en"}, {"?lang=zh", "zh-Hant"}, {"?lang=zh-Hant", "zh-Hant"}, {"?lang=de", "en"},
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/projects/1/sboms/測試版本/report"+tt.query, nil))
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "application/pdf", w.Header().Get("Content-Type"))
		require.Equal(t, tt.language, w.Header().Get("Content-Language"))
		require.Contains(t, w.Body.String()[:5], "%PDF-")
		disposition, params, err := mime.ParseMediaType(w.Header().Get("Content-Disposition"))
		require.NoError(t, err)
		require.Equal(t, "attachment", disposition)
		require.Contains(t, params["filename"], "測試版本")
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/projects/2/sboms/測試版本/report", nil))
	require.Equal(t, http.StatusNotFound, w.Code)
	require.NotContains(t, w.Body.String(), "%PDF-")
}

type reportRepository struct{ repository.Repository }

func (reportRepository) GetProjects() ([]domain.ProjectInfo, error) {
	return []domain.ProjectInfo{{ID: 1, Name: "測試專案"}}, nil
}
