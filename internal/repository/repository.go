// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package repository

import (
	"gorm.io/gorm"
)

// SBOMRepository handles persistence of SBOM results.
type SBOMRepository struct {
	db *gorm.DB
}

// NewSBOMRepository creates a new SBOMRepository.
func NewSBOMRepository(db *gorm.DB) *SBOMRepository {
	return &SBOMRepository{db: db}
}
