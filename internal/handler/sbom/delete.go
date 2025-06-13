// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package sbom

import (
	ssbom "ex-sbom/internal/service/sbom"
	"ex-sbom/util/msg"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

func DeleteSBOM(c *gin.Context) {
	name := c.Query("name")
	if len(name) == 0 {
		slog.Error("Missing SBOM name", "error", msg.ErrMissingParam)

		c.JSON(http.StatusBadRequest, gin.H{msg.RespErr: fmt.Sprintf(msg.ErrMissingParam, "name")})
		return
	}

	if _, exists := SBOMs[name]; !exists {
		slog.Error("SBOM not found", "name", name)

		c.JSON(http.StatusNotFound, gin.H{msg.RespErr: msg.ErrSBOMNotFound})
		return
	}

	delete(SBOMs, name)
	ssbom.DeleteSBOM(name)

	slog.Info("SBOM deleted successfully", "name", name)

	c.JSON(http.StatusOK, gin.H{msg.RespMsg: "ok"})
}
