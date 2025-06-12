// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package unique

func StringSlice(input []string) []string {
	unique := make(map[string]struct{})
	for _, str := range input {
		unique[str] = struct{}{}
	}

	result := make([]string, 0, len(unique))
	for str := range unique {
		result = append(result, str)
	}

	return result
}
