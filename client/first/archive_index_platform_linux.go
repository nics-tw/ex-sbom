// SPDX-License-Identifier: MIT

package first

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func archiveChangeTime(stat *syscall.Stat_t) int64 { return stat.Ctim.Nano() }

func publishArchiveDirectory(staging, output string) error {
	return unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE)
}
