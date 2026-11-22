// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	osvQueryURL = "https://api.osv.dev/v1/query"
	// Probe the official query endpoint using a fixed public package and version.
	osvQueryBody = `{"version":"v1.0.0","package":{"ecosystem":"Go","name":"github.com/google/uuid"}}`
)

type osvProbeError struct {
	endpoint string
	stage    string
	status   int
	action   string
}

func (e *osvProbeError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("OSV preflight %s (%s, HTTP %d): %s", e.endpoint, e.stage, e.status, e.action)
	}
	return fmt.Sprintf("OSV preflight %s (%s): %s", e.endpoint, e.stage, e.action)
}

func checkNetworkConnectivity() error {
	client := &http.Client{Timeout: 5 * time.Second}
	status, err := probeOSV(context.Background(), client, osvQueryURL)
	if err != nil {
		return err
	}
	slog.Info("OSV preflight query succeeded", "endpoint", osvQueryURL, "status", status)
	return nil
}

func probeOSV(ctx context.Context, client *http.Client, endpoint string) (int, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return 0, &osvProbeError{endpoint: "OSV API", stage: "request", action: "Check the configured OSV endpoint."}
	}
	u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
	safeEndpoint := u.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, safeEndpoint, strings.NewReader(osvQueryBody))
	if err != nil {
		return 0, &osvProbeError{endpoint: safeEndpoint, stage: "request", action: "Check the configured OSV endpoint."}
	}
	req.Header.Set("Content-Type", "application/json")

	probeClient := *client
	probeClient.Jar = nil
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := probeClient.Do(req)
	if err != nil {
		stage, action := osvConnectionDiagnostic(err)
		return 0, &osvProbeError{endpoint: safeEndpoint, stage: stage, action: action}
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	if code >= 200 && code < 300 {
		return code, nil
	}
	stage, action := osvHTTPDiagnostic(code)
	return code, &osvProbeError{endpoint: safeEndpoint, stage: stage, status: code, action: action}
}

func osvConnectionDiagnostic(err error) (stage, action string) {
	var networkErr net.Error
	var dnsErr *net.DNSError
	var dialErr *net.OpError
	var verifyErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	var alertErr tls.AlertError
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &networkErr) && networkErr.Timeout():
		return "timeout", "Check network or proxy latency and retry."
	case errors.As(err, &dnsErr):
		return "dns", "Check DNS resolution and proxy settings."
	case errors.As(err, &verifyErr), errors.As(err, &recordErr), errors.As(err, &alertErr):
		return "tls handshake", "Check the system clock, trusted certificates, and proxy TLS settings."
	case errors.As(err, &dialErr) && dialErr.Op == "dial":
		return "tcp connection", "Check network access, firewall rules, and proxy settings."
	default:
		return "connection", "Check network access and proxy settings."
	}
}

func osvHTTPDiagnostic(code int) (stage, action string) {
	switch {
	case code >= 300 && code < 400:
		return "http redirect", "Check the endpoint and whether a proxy or network sign-in is redirecting the request."
	case code == http.StatusUnauthorized:
		return "http authentication", "Check whether a proxy or network gateway requires authentication."
	case code == http.StatusForbidden:
		return "http authorization", "Check whether network policy allows access to the OSV endpoint."
	case code == http.StatusTooManyRequests:
		return "http rate limit", "Wait and retry the preflight."
	case code >= 400 && code < 500:
		return "http client", "Check the OSV endpoint, request format, and proxy policy."
	case code >= 500 && code < 600:
		return "http server", "Check OSV service status and retry."
	default:
		return "http response", "Check the OSV endpoint and proxy response."
	}
}
