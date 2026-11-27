// SPDX-License-Identifier: MIT

package first

import (
	"context"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func archiveChangeTime(stat *syscall.Stat_t) int64 { return stat.Ctim.Nano() }

func sealAndPublishArchiveDirectory(ctx context.Context, staging, output string) error {
	if err := sealArchiveDirectory(staging); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE); err != nil {
		return &os.LinkError{Op: "publish archive", Old: staging, New: output, Err: err}
	}
	return nil
}
