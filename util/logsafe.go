// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package util

import "strings"

// logSafeReplacer strips CR/LF so user-provided values cannot forge log lines.
var logSafeReplacer = strings.NewReplacer("\n", "", "\r", "")

// LogSafe sanitizes a user-provided value for logging by removing newline
// characters, preventing log-entry injection (CodeQL: log entries created
// from user input).
func LogSafe(s string) string {
	return logSafeReplacer.Replace(s)
}
