// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT

//go:build e2e

package main

import (
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
	http.DefaultTransport = e2eOSVTransport{fail: os.Getenv("EX_SBOM_E2E_FAIL_SCAN") == "1"}
	t.Cleanup(func() { http.DefaultTransport = transport })

	if err := db.Init(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	repo := repository.NewSBOMRepository(db.GormDB)
	cache := ssbom.NewInMemoryCache()
	loadInitialData(repo, cache)
	gin.SetMode(gin.TestMode)
	server := &http.Server{
		Handler:           createServer(psvc.New(repo, cache), ssbom.NewService(repo, cache)),
		ReadHeaderTimeout: 5 * time.Second,
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

// e2eOSVTransport exercises the real scanner with deterministic query results.
type e2eOSVTransport struct{ fail bool }

func (transport e2eOSVTransport) RoundTrip(req *http.Request) (*http.Response, error) {
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
		Queries []json.RawMessage `json:"queries"`
	}
	if err := json.NewDecoder(req.Body).Decode(&query); err != nil {
		return nil, err
	}
	reply, err := json.Marshal(struct {
		Results []struct{} `json:"results"`
	}{Results: make([]struct{}, len(query.Queries))})
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(reply))),
		Request:    req,
	}, nil
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
