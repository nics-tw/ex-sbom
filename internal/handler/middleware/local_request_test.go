// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestLocalBrowserRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(LocalBrowserRequest())
	router.Any("/request", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	tests := []struct {
		name, method, host, origin, referer, fetchSite string
		want                                           int
	}{
		{"IPv4 browser URL", http.MethodGet, "127.0.0.1:8080", "", "", "", http.StatusNoContent},
		{"IPv6 browser URL", http.MethodGet, "[::1]:8080", "", "", "", http.StatusNoContent},
		{"local hostname", http.MethodGet, "localhost:8080", "", "", "", http.StatusNoContent},
		{"other loopback address", http.MethodGet, "127.0.0.2:8080", "", "", "", http.StatusNoContent},
		{"rebound hostname", http.MethodGet, "attacker.example:8080", "", "", "", http.StatusForbidden},
		{"malformed host", http.MethodGet, "localhost:bad", "", "", "", http.StatusForbidden},
		{"cross-origin text POST", http.MethodPost, "localhost:8080", "https://attacker.example", "", "cross-site", http.StatusForbidden},
		{"cross-origin PUT", http.MethodPut, "localhost:8080", "http://127.0.0.1:8080", "", "", http.StatusForbidden},
		{"opaque origin", http.MethodPost, "localhost:8080", "null", "", "", http.StatusForbidden},
		{"same-origin POST", http.MethodPost, "localhost:8080", "http://localhost:8080", "", "same-origin", http.StatusNoContent},
		{"same-origin IPv6 POST", http.MethodPost, "[::1]:8080", "http://[::1]:8080", "", "", http.StatusNoContent},
		{"CLI without Origin", http.MethodPost, "localhost:8080", "", "", "", http.StatusNoContent},
		{"cross-site fetch metadata", http.MethodPost, "localhost:8080", "", "", "cross-site", http.StatusForbidden},
		{"same-origin Referer with query", http.MethodPost, "localhost:8080", "", "http://localhost:8080/tutorial?q=1", "", http.StatusNoContent},
		{"cross-origin Referer", http.MethodPost, "localhost:8080", "", "http://attacker.example/", "", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/request", nil)
			req.Host = tt.host
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			if tt.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.fetchSite)
			}
			res := httptest.NewRecorder()
			router.ServeHTTP(res, req)
			assert.Equal(t, tt.want, res.Code)
		})
	}
}
