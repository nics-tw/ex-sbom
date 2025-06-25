// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package util

func Multiply(values []float64) float64 {
	result := 1.0
	for _, v := range values {
		result *= v
	}

	return result
}
