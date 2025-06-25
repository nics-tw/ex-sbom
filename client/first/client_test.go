// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package first

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComposeParam(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "Empty input",
			input:    []string{},
			expected: "",
		},
		{
			name:     "Single element",
			input:    []string{"CVE-2023-12345"},
			expected: "https://api.first.org/data/v1/epss?cve=CVE-2023-12345&scope=time-series",
		},
		{
			name:     "Multiple elements",
			input:    []string{"CVE-2023-12345", "CVE-2023-67890"},
			expected: "https://api.first.org/data/v1/epss?cve=CVE-2023-12345,CVE-2023-67890&scope=time-series",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := composeParam(tt.input)
			if !assert.Equal(t, tt.expected, result) {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetLEV(t *testing.T) {
	tests := []struct {
		name     string
		input    []TimeSeries
		expected float64
	}{
		{
			name:     "Valid single CVE",
			input:    []TimeSeries{{EPSS: "0.5", Percentile: "0.5", Date: "2023-01-01"}},
			expected: 0.5,
		},
		{
			name: "Valid multiple CVEs",
			input: []TimeSeries{{EPSS: "0.3", Percentile: "0.3", Date: "2023-01-01"},
				{EPSS: "0.7", Percentile: "0.7", Date: "2023-01-02"}},
			expected: 0.853,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getLEV(tt.input)
			if !assert.Equal(t, tt.expected, result) {
				t.Errorf("expected %f, got %f", tt.expected, result)
			}
		})
	}
}
