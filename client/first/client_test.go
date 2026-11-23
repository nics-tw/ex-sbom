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

func TestCalculateLEV(t *testing.T) {
	for _, tc := range []struct {
		name   string
		series []TimeSeries
		want   float64
		valid  bool
	}{
		{"full window and one-day tail", []TimeSeries{{Date: "2023-01-31", EPSS: "0.3"}, {Date: "2023-01-02", EPSS: "0.9"}, {Date: "2023-01-01", EPSS: "0.3"}}, .307, true},
		{"valid zero", []TimeSeries{{Date: "2023-01-01", EPSS: "0"}, {Date: "2023-01-31", EPSS: "0"}}, 0, true},
		{"missing first window", []TimeSeries{{Date: "2023-01-31", EPSS: "0.3"}}, 0, false},
		{"missing tail window", []TimeSeries{{Date: "2023-01-01", EPSS: "0.3"}, {Date: "2023-02-01", EPSS: "0.9"}}, 0, false},
		{"conflicting duplicate", []TimeSeries{{Date: "2023-01-01", EPSS: "0.3"}, {Date: "2023-01-01", EPSS: "0.4"}}, 0, false},
		{"nonfinite", []TimeSeries{{Date: "2023-01-01", EPSS: "NaN"}}, 0, false},
		{"out of range", []TimeSeries{{Date: "2023-01-01", EPSS: "1.01"}}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, valid := CalculateLEV(tc.series, "2023-01-01", "2023-01-31")
			assert.Equal(t, tc.valid, valid)
			assert.InDelta(t, tc.want, got, 1e-12)
		})
	}
}
