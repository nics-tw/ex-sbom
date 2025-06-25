// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package util

import "testing"

func TestMultiply(t *testing.T) {
	tests := []struct {
		name     string
		input    []float64
		expected float64
	}{
		{
			name:     "empty slice",
			input:    []float64{},
			expected: 1.0,
		},
		{
			name:     "single element",
			input:    []float64{5.0},
			expected: 5.0,
		},
		{
			name:     "multiple elements",
			input:    []float64{2.0, 3.0, 4.0},
			expected: 24.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Multiply(tt.input)
			if result != tt.expected {
				t.Errorf("expected %f, got %f", tt.expected, result)
			}
		})
	}
}
