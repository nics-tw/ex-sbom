// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package first

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type (
	EPSSResponse struct {
		Status     string `json:"status"`
		StatusCode int    `json:"status-code"`
		Version    string `json:"version"`
		Access     string `json:"access"`
		Total      int    `json:"total"`
		Offset     int    `json:"offset"`
		Limit      int    `json:"limit"`
		Data       []EPSS `json:"data"`
	}

	EPSS struct {
		CVE        string       `json:"cve"`
		EPSS       string       `json:"epss"`
		Percentile string       `json:"percentile"`
		Date       string       `json:"date"`
		TimeSeries []TimeSeries `json:"time-series"`
	}

	TimeSeries struct {
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	}

	Client struct {
		HttpClient *http.Client
	}
)

const (
	BaseURL = "https://api.first.org/data/v1/epss"
	Pcve    = "?cve="
)

func New() *Client {
	return &Client{
		HttpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *Client) GetEPSS(cves []string) (*EPSSResponse, error) {
	reqURL := composeParam(cves)

	resp, err := c.HttpClient.Get(reqURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch EPSS data: %s", resp.Status)
	}

	var epssResponse EPSSResponse
	if err := json.NewDecoder(resp.Body).Decode(&epssResponse); err != nil {
		return nil, err
	}

	return &epssResponse, nil
}

func composeParam(cves []string) string {
	if len(cves) == 0 {
		return ""
	}

	var p strings.Builder

	p.WriteString(BaseURL)
	p.WriteString(Pcve)

	for i, cve := range cves {
		if i > 0 {
			p.WriteString(",")
		}

		p.WriteString(cve)
	}

	return p.String()
}
