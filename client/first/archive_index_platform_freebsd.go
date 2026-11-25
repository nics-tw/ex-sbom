// SPDX-License-Identifier: MIT

package first

import (
	"context"
	"errors"
	"syscall"
)

func archiveChangeTime(stat *syscall.Stat_t) int64 { return stat.Ctimespec.Nano() }

func sealAndPublishArchiveDirectory(context.Context, string, string) error {
	return errors.New("atomic LEV archive snapshot publication is unavailable on FreeBSD")
}
