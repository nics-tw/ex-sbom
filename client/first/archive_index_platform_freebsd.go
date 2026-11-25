// SPDX-License-Identifier: MIT

package first

import (
	"errors"
	"syscall"
)

func archiveChangeTime(stat *syscall.Stat_t) int64 { return stat.Ctimespec.Nano() }

func publishArchiveDirectory(staging, output string) error {
	return errors.New("atomic LEV archive snapshot publication is unavailable on FreeBSD")
}
