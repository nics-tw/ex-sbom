// SPDX-License-Identifier: MIT

//go:build !taggedpdf

package pdf

import (
	"context"
	"io"
)

func GenerateContext(ctx context.Context, w io.Writer, report Report) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return generateUntagged(w, report)
}
