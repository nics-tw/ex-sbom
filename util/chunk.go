// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package util

func ChunkSlice(a []string, chunkSize int) [][]string {
	if len(a) == 0 || chunkSize <= 0 {
		return nil
	}

	var chunks [][]string
	for i := 0; i < len(a); i += chunkSize {
		end := i + chunkSize
		if end > len(a) {
			end = len(a)
		}
		chunks = append(chunks, a[i:end])
	}

	return chunks
}
