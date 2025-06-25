// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunkSlice(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		chunkSize int
		expected  [][]string
	}{
		{
			name:      "Empty slice",
			input:     []string{},
			chunkSize: 2,
			expected:  nil,
		},
		{
			name:      "Single element",
			input:     []string{"a"},
			chunkSize: 1,
			expected:  [][]string{{"a"}},
		},
		{
			name:      "Multiple elements, chunk size 2",
			input:     []string{"a", "b", "c", "d"},
			chunkSize: 2,
			expected:  [][]string{{"a", "b"}, {"c", "d"}},
		},
		{
			name:      "Chunk size larger than slice length",
			input:     []string{"a", "b"},
			chunkSize: 5,
			expected:  [][]string{{"a", "b"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ChunkSlice(tt.input, tt.chunkSize)
			if !assert.ElementsMatch(t, tt.expected, result) {
				t.Errorf("ChunkSlice(%v, %d) = %v; want %v", tt.input, tt.chunkSize, result, tt.expected)
			}
		})
	}
}
