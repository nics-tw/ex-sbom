// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package middleware

import (
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// JSONContentType keeps browser simple requests from reaching JSON mutation
// handlers, even when older clients omit Origin and Fetch Metadata headers.
func JSONContentType() gin.HandlerFunc {
	return func(c *gin.Context) {
		mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
		if err != nil || mediaType != "application/json" {
			c.AbortWithStatus(http.StatusUnsupportedMediaType)
			return
		}
		c.Next()
	}
}

// LocalBrowserRequest rejects DNS-rebound Host headers and cross-origin
// browser mutations. Requests from local CLI tools may omit browser headers.
func LocalBrowserRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !localHost(c.Request.Host) || !localMutation(c.Request) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

func localHost(raw string) bool {
	var host, port string
	if strings.HasPrefix(raw, "[") {
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return false
		}
		host = raw[1:end]
		rest := raw[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return false
			}
			port = rest[1:]
		}
	} else {
		if strings.Count(raw, ":") > 1 {
			return false
		}
		host = raw
		if i := strings.LastIndexByte(raw, ':'); i >= 0 {
			host, port = raw[:i], raw[i+1:]
		}
	}

	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	} else if strings.HasSuffix(raw, ":") {
		return false
	}

	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func localMutation(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}

	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if origins := r.Header.Values("Origin"); len(origins) != 0 {
		return len(origins) == 1 && sameLocalOrigin(origins[0], r.Host, false)
	}
	if referrers := r.Header.Values("Referer"); len(referrers) != 0 {
		return len(referrers) == 1 && sameLocalOrigin(referrers[0], r.Host, true)
	}
	return true
}

func sameLocalOrigin(raw, host string, allowPath bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || !strings.EqualFold(u.Host, host) ||
		u.Opaque != "" || (!allowPath && (u.Path != "" || u.RawQuery != "" || u.Fragment != "")) {
		return false
	}
	return true
}
