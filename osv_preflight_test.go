//go:build unit

// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbeOSVHTTPStatus(t *testing.T) {
	redirects := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			select {
			case redirects <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		var query struct {
			Version string
			Package struct {
				Name, Ecosystem string
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
			t.Errorf("decode OSV query: %v", err)
		}
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" ||
			query.Version != "v1.0.0" || query.Package.Name != "github.com/google/uuid" ||
			query.Package.Ecosystem != "Go" {
			t.Errorf("unexpected OSV query: method=%q content-type=%q payload=%+v", r.Method, r.Header.Get("Content-Type"), query)
		}
		if r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" {
			t.Error("preflight must omit credentials and query parameters")
		}

		var status int
		if _, err := fmt.Sscanf(r.URL.Path, "/%d", &status); err != nil {
			t.Errorf("unexpected test path: %q", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "/redirected?token=location-secret")
		w.WriteHeader(status)
	}))
	defer server.Close()

	tests := []struct {
		status int
		stage  string
	}{
		{http.StatusOK, ""},
		{http.StatusNoContent, ""},
		{http.StatusTemporaryRedirect, "http redirect"},
		{http.StatusUnauthorized, "http authentication"},
		{http.StatusForbidden, "http authorization"},
		{http.StatusTooManyRequests, "http rate limit"},
		{http.StatusNotFound, "http client"},
		{http.StatusServiceUnavailable, "http server"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			endpoint := strings.Replace(server.URL, "http://", "http://user:password-secret@", 1) +
				fmt.Sprintf("/%d?token=query-secret#fragment-secret", tc.status)
			status, err := probeOSV(context.Background(), server.Client(), endpoint)
			if status != tc.status {
				t.Fatalf("status = %d, want %d (error = %v)", status, tc.status, err)
			}
			if tc.stage == "" {
				if err != nil {
					t.Fatalf("probe returned %v", err)
				}
				return
			}
			assertProbeError(t, err, tc.stage, server.URL, tc.status)
		})
	}
	select {
	case <-redirects:
		t.Error("unexpected request to redirect destination")
	default:
	}
}

func TestProbeOSVConnectionErrors(t *testing.T) {
	transportErrors := []struct {
		stage string
		err   error
	}{
		{"dns", &net.DNSError{Err: "dns-secret", Name: "test.invalid"}},
		{"tcp connection", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("dial-secret")}},
		{"connection", errors.New("transport-secret")},
	}
	for _, tc := range transportErrors {
		t.Run(tc.stage, func(t *testing.T) {
			const endpoint = "https://example.invalid/v1/query"
			client := &http.Client{
				Transport: probeTransportFunc(func(*http.Request) (*http.Response, error) {
					return nil, tc.err
				}),
			}
			status, err := probeOSV(context.Background(), client, endpoint)
			if status != 0 {
				t.Fatalf("status = %d, want 0", status)
			}
			assertProbeError(t, err, tc.stage, endpoint, 0)
		})
	}
}

func TestProbeOSVTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	endpoint := server.URL + "/v1/query"
	if _, err := probeOSV(context.Background(), server.Client(), endpoint); err != nil {
		t.Fatalf("trusted TLS probe returned %v", err)
	}
	_, err := probeOSV(context.Background(), &http.Client{}, endpoint)
	assertProbeError(t, err, "tls handshake", endpoint, 0)
}

func TestProbeOSVTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)
	client := server.Client()
	client.Timeout = 50 * time.Millisecond
	endpoint := server.URL + "/v1/query"
	_, err := probeOSV(context.Background(), client, endpoint)
	assertProbeError(t, err, "timeout", endpoint, 0)
}

type probeTransportFunc func(*http.Request) (*http.Response, error)

func (f probeTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func assertProbeError(t *testing.T, err error, stage, endpoint string, status int) {
	t.Helper()
	var got *osvProbeError
	if !errors.As(err, &got) {
		t.Fatalf("probe error = %v, want *osvProbeError", err)
	}
	if got.stage != stage || got.status != status {
		t.Fatalf("unexpected stage or status: %v", got)
	}
	msg := got.Error()
	if !strings.Contains(msg, endpoint) || !strings.Contains(msg, stage) || got.action == "" ||
		!strings.Contains(msg, got.action) || strings.Contains(msg, "-secret") ||
		(status != 0 && !strings.Contains(msg, fmt.Sprintf("HTTP %d", status))) {
		t.Errorf("incomplete or unsafe diagnostic: %q", msg)
	}
}
