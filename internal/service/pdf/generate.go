// SPDX-License-Identifier: MIT

package pdf

import (
	"context"
	"errors"
	"io"
)

// ErrCacheUnavailable means the application could not prepare or run its PDF renderer cache.
var ErrCacheUnavailable = errors.New("PDF renderer cache unavailable")

func Generate(w io.Writer, report Report) error {
	return GenerateContext(context.Background(), w, report)
}
