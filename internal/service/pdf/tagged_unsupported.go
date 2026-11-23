// SPDX-License-Identifier: MIT

//go:build taggedpdf && !((darwin && !ios && arm64) || (linux && !android && (arm64 || amd64)))

package pdf

var _ = taggedPDFRequiresDarwinARM64LinuxARM64OrLinuxAMD64
