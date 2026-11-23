// SPDX-License-Identifier: MIT

//go:build !taggedpdf

package pdf

import "io"

func Generate(w io.Writer, report Report) error {
	return generateUntagged(w, report)
}
