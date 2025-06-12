// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetPackageName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with path separator",
			input:    "symfony/http-foundation",
			expected: "http-foundation",
		},
		{
			name:     "without path separator",
			input:    "simple-package",
			expected: "simple-package",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "multiple separators",
			input:    "org/group/package-name",
			expected: "package-name",
		},
		{
			name:     "trailing separator",
			input:    "package/",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPackageName(tt.input)
			if !assert.Equal(t, tt.expected, result) {
				t.Errorf("getPackageName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
