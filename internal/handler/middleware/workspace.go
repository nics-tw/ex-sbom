// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package middleware

import (
	"net/http"
	"strconv"

	"ex-sbom/internal/domain"

	"github.com/gin-gonic/gin"
)

const ProjectIDKey = "projectID"

// ProjectID is a Gin middleware that parses the :id path parameter into an int64
// and stores it in the context under ProjectIDKey.
func ProjectID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || id == 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid project id"})
			return
		}

		c.Set(ProjectIDKey, id)
		c.Next()
	}
}

// GetProjectID retrieves the project ID that was stored by the ProjectID middleware.
func GetProjectID(c *gin.Context) domain.ProjectID {
	id, _ := c.Get(ProjectIDKey)
	return id.(int64)
}
