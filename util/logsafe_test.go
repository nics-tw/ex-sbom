// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogSafe(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "plain value untouched", input: "v1.2.3", expected: "v1.2.3"},
		{name: "strips LF", input: "v1\ninjected line", expected: "v1injected line"},
		{name: "strips CR", input: "v1\rinjected", expected: "v1injected"},
		{name: "strips CRLF", input: "v1\r\nERROR forged entry", expected: "v1ERROR forged entry"},
		{name: "empty string", input: "", expected: ""},
		{name: "unicode preserved", input: "版本一", expected: "版本一"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, LogSafe(tt.input))
		})
	}
}
