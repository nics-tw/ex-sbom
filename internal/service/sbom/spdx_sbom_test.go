//go:build unit

package ssbom

import (
	"testing"

	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/stretchr/testify/assert"
)

func TestGetRefIDStr(t *testing.T) {
	tests := []struct {
		name  string
		input common.DocElementID
		want  string
	}{
		{
			name: "should return DocumentRefID if present",
			input: common.DocElementID{
				DocumentRefID: "doc-1",
				ElementRefID:  "elem-1",
				SpecialID:     "special-1",
			},
			want: "doc-1",
		},
		{
			name: "should return ElementRefID if DocumentRefID empty",
			input: common.DocElementID{
				DocumentRefID: "",
				ElementRefID:  "elem-1",
				SpecialID:     "special-1",
			},
			want: "elem-1",
		},
		{
			name: "should return SpecialID if others empty",
			input: common.DocElementID{
				DocumentRefID: "",
				ElementRefID:  "",
				SpecialID:     "special-1",
			},
			want: "special-1",
		},
		{
			name: "should return empty string if all empty",
			input: common.DocElementID{
				DocumentRefID: "",
				ElementRefID:  "",
				SpecialID:     "",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getRefIDStr(tt.input)
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("getRefIDStr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrimSPDXPrefix(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "should trim SPDXRef prefix",
			input: "SPDXRef-component",
			want:  "component",
		},
		{
			name:  "should trim DocumentRef prefix",
			input: "DocumentRef-doc",
			want:  "doc",
		},
		{
			name:  "should return original string if no prefix",
			input: "regular-component",
			want:  "regular-component",
		},
		{
			name:  "should return empty string for empty input",
			input: "",
			want:  "",
		},
		{
			name:  "should handle case with both prefixes",
			input: "SPDXRef-DocumentRef-test",
			want:  "DocumentRef-test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimSPDXPrefix(tt.input)
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("trimSPDXPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsGeneratedRoot(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "should return true for DOCUMENT",
			input: "DOCUMENT",
			want:  true,
		},
		{
			name:  "should return true for DocumentRoot prefix",
			input: "DocumentRoot-test",
			want:  true,
		},
		{
			name:  "should return true for File prefix",
			input: "File-test",
			want:  true,
		},
		{
			name:  "should return false for regular component ID",
			input: "component-1",
			want:  false,
		},
		{
			name:  "should return false for empty string",
			input: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGeneratedRoot(tt.input)
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("isGeneratedRoot() = %v, want %v", got, tt.want)
			}
		})
	}
}
