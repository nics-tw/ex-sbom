// SPDX-License-Identifier: MIT

package first

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func archiveChangeTime(stat *syscall.Stat_t) int64 { return stat.Ctimespec.Nano() }

func sealAndPublishArchiveDirectory(ctx context.Context, staging, output string) error {
	dir, err := os.Open(staging)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.RenameatxNp(unix.AT_FDCWD, staging, unix.AT_FDCWD, output, unix.RENAME_EXCL); err != nil {
		return &os.LinkError{Op: "publish archive", Old: staging, New: output, Err: err}
	}
	// Older Darwin requires write permission when moving a directory. Readers
	// reject the new name until the same directory is sealed through this fd.
	if err := dir.Chmod(0500); err != nil {
		rollback := unix.RenameatxNp(unix.AT_FDCWD, output, unix.AT_FDCWD, staging, unix.RENAME_EXCL)
		if rollback != nil {
			rollback = &os.LinkError{Op: "restore archive staging", Old: output, New: staging, Err: rollback}
		}
		return errors.Join(fmt.Errorf("seal published archive %s: %w", output, err), rollback)
	}
	return nil
}
