//go:build unit

package unique

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "slice with duplicates",
			input:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "slice without duplicates",
			input:    []string{"x", "y", "z"},
			expected: []string{"x", "y", "z"},
		},
		{
			name:     "slice with empty strings",
			input:    []string{"", "test", ""},
			expected: []string{"", "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StringSlice(tt.input)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}
