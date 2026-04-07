// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package sbom

import (
	"testing"

	"ex-sbom/util/msg"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestToCreateResponse(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedMsg string
	}{
		{name: "normal version", input: "v1.0", expectedMsg: "ok"},
		{name: "empty version", input: "", expectedMsg: "ok"},
		{name: "unicode version", input: "測試版本", expectedMsg: "ok"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := []string{}
			if tt.input != "" {
				names = []string{tt.input}
			}
			result := toCreateResponse(1, names)

			assert.IsType(t, gin.H{}, result)
			assert.Equal(t, tt.expectedMsg, result[msg.RespMsg])
		})
	}
}
