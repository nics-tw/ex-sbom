// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package middleware

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

const WorkspaceIDKey = "workspaceID"

// WorkspaceID is a Gin middleware that parses the :id path parameter into an int64
// and stores it in the context under WorkspaceIDKey.
func WorkspaceID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || id == 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid workspace id"})
			return
		}
		c.Set(WorkspaceIDKey, id)
		c.Next()
	}
}

// GetWorkspaceID retrieves the workspace ID that was stored by the WorkspaceID middleware.
func GetWorkspaceID(c *gin.Context) int64 {
	id, _ := c.Get(WorkspaceIDKey)
	return id.(int64)
}