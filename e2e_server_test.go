// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT

//go:build e2e

package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"ex-sbom/internal/db"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"
	psvc "ex-sbom/internal/service/workspace"

	"github.com/gin-gonic/gin"
)

func TestE2EServer(t *testing.T) {
	path := os.Getenv("DB_PATH")
	if path == "" {
		t.Skip("start through the browser fixture, with a temporary DB_PATH")
	}
	transport := http.DefaultTransport
	http.DefaultTransport = e2eOSVTransport{
		fail:          os.Getenv("EX_SBOM_E2E_FAIL_SCAN") == "1",
		failRiskFeeds: os.Getenv("EX_SBOM_E2E_FAIL_RISK_FEEDS") == "1",
	}
	t.Cleanup(func() { http.DefaultTransport = transport })
	if os.Getenv("EX_SBOM_E2E_HISTORY") == "1" {
		seedE2EEPSSHistory(t)
	}

	if err := db.Init(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	repo := repository.NewSBOMRepository(db.GormDB)
	cache := ssbom.NewInMemoryCache()
	loadInitialData(repo, cache)
	gin.SetMode(gin.TestMode)
	server := &http.Server{
		Handler: createServer(psvc.New(repo, cache), ssbom.NewService(repo, cache)),
		// Close speculative browser sockets before the five-second shutdown deadline.
		ReadHeaderTimeout: 2 * time.Second,
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	fmt.Printf("EX_SBOM_E2E_URL=http://%s\n", listener.Addr())

	select {
	case err := <-serveDone:
		t.Fatalf("test service stopped before shutdown: %v", err)
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			t.Fatal(err)
		}
		if err := <-serveDone; !errors.Is(err, http.ErrServerClosed) {
			t.Fatal(err)
		}
	}
}

func seedE2EEPSSHistory(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	asOf := time.Now().UTC().AddDate(0, 0, -1)
	start := asOf.AddDate(0, 0, -29)
	archive, err := os.Create(filepath.Join(dir, "epss_scores-"+start.Format(time.DateOnly)+".csv.gz"))
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(archive)
	_, writeErr := fmt.Fprintf(compressed, "#model_version:fixture,score_date:%sT00:00:00+0000\ncve,epss,percentile\nCVE-2025-99999,0.37,0.95\n", start.Format(time.DateOnly))
	if err := errors.Join(writeErr, compressed.Close(), archive.Close()); err != nil {
		t.Fatal(err)
	}
	reservations := filepath.Join(dir, "reservations.json")
	if err := os.WriteFile(reservations, []byte(fmt.Sprintf(`{"CVE-2025-99999":%q}`, start.Format(time.DateOnly))), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EPSS_ARCHIVE_DIR", dir)
	t.Setenv("CVE_RESERVATIONS_FILE", reservations)
}

// e2eOSVTransport exercises the real scanner with deterministic query results.
type e2eOSVTransport struct{ fail, failRiskFeeds bool }

func (transport e2eOSVTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet {
		switch req.URL.Host + req.URL.Path {
		case "api.osv.dev/v1/vulns/EX-SBOM-TEST-1":
			return e2eJSON(req, `{
				"id":"EX-SBOM-TEST-1","aliases":["CVE-2025-99999"],
				"modified":"2025-01-01T00:00:00Z","summary":"Synthetic remediation finding",
				"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
				"affected":[{"package":{"ecosystem":"npm","name":"fixture-remediation"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]
			}`), nil
		case "api.osv.dev/v1/vulns/EX-SBOM-TEST-2":
			return e2eJSON(req, `{
				"id":"EX-SBOM-TEST-2","aliases":["CVE-2025-99998"],
				"modified":"2025-01-01T00:00:00Z","summary":"Unlisted synthetic finding",
				"affected":[{"package":{"ecosystem":"npm","name":"fixture-remediation"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]
			}`), nil
		case "api.osv.dev/v1/vulns/EX-SBOM-GO-FIX":
			return e2eJSON(req, `{"id":"EX-SBOM-GO-FIX","modified":"2025-01-01T00:00:00Z","summary":"Go advisory candidate fixture","affected":[{"package":{"ecosystem":"Go","name":"example.com/widget"},"ranges":[{"type":"GIT","repo":"https://example.com/widget","events":[{"introduced":"0"},{"fixed":"1.2.4"}]}]}]}`), nil
		case "api.first.org/data/v1/epss":
			if transport.failRiskFeeds {
				return nil, errors.New("fixture EPSS source unavailable")
			}
			return e2eJSON(req, `{"data":[{"cve":"CVE-2025-99999","epss":"0.2","date":"2025-01-02"}]}`), nil
		case "www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json":
			if transport.failRiskFeeds {
				return nil, errors.New("fixture KEV source unavailable")
			}
			return e2eJSON(req, `{"catalogVersion":"synthetic","count":1,"vulnerabilities":[{"cveID":"CVE-2025-99999"}]}`), nil
		}
	}
	if req.Body != nil {
		defer req.Body.Close()
	}
	if req.URL.Scheme != "https" || req.URL.Host != "api.osv.dev" ||
		req.URL.Path != "/v1/querybatch" || req.Method != http.MethodPost {
		return nil, fmt.Errorf("unexpected outbound request in browser fixture: %s %s", req.Method, req.URL.Host+req.URL.Path)
	}
	if transport.fail {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Status:     "400 Bad Request",
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"message":"controlled scan failure"}`)),
			Request:    req,
		}, nil
	}
	var query struct {
		Queries []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
		} `json:"queries"`
	}
	if err := json.NewDecoder(req.Body).Decode(&query); err != nil {
		return nil, err
	}
	results := make([]json.RawMessage, len(query.Queries))
	for i, item := range query.Queries {
		results[i] = json.RawMessage(`{}`)
		if item.Package.Name == "fixture-remediation" {
			results[i] = json.RawMessage(`{"vulns":[{"id":"EX-SBOM-TEST-1"},{"id":"EX-SBOM-TEST-2"}]}`)
		}
		if item.Package.Name == "example.com/widget" {
			results[i] = json.RawMessage(`{"vulns":[{"id":"EX-SBOM-GO-FIX"}]}`)
		}
	}
	reply, err := json.Marshal(struct {
		Results []json.RawMessage `json:"results"`
	}{Results: results})
	if err != nil {
		return nil, err
	}
	return e2eJSON(req, string(reply)), nil
}

func e2eJSON(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

// Store valid JSON with an incompatible shape to exercise the same corrupt-row
// handling a database from an incompatible app version would require.
func TestCorruptedRecordsStayOutOfAnalysis(t *testing.T) {
	if err := db.Init(filepath.Join(t.TempDir(), "corrupted.duckdb")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	repo := repository.NewSBOMRepository(db.GormDB)
	projectID, err := repo.CreateProject("fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSBOM(projectID, "readable", ssbom.FormattedSBOM{}, time.Time{}, "readable"); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSBOM(projectID, "corrupted", []string{"not a structured SBOM"}, time.Time{}, "corrupted"); err != nil {
		t.Fatal(err)
	}
	cache := ssbom.NewInMemoryCache()
	loadInitialData(repo, cache)
	gin.SetMode(gin.TestMode)
	server := createServer(psvc.New(repo, cache), ssbom.NewService(repo, cache))
	projectURL := fmt.Sprintf("http://127.0.0.1/projects/%d", projectID)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, projectURL, nil))
	var payload struct {
		Data struct {
			SBOMs     []string `json:"sboms"`
			Corrupted []string `json:"corrupted"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(payload.Data.SBOMs) != 1 ||
		payload.Data.SBOMs[0] != "readable" || len(payload.Data.Corrupted) != 1 || payload.Data.Corrupted[0] != "corrupted" {
		t.Fatalf("unexpected project reload response: %d %s", response.Code, response.Body)
	}
	response = httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, projectURL+"/sboms/corrupted/topology", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("unexpected corrupt-version topology response: %d %s", response.Code, response.Body)
	}
}
