// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"ex-sbom/client/first"
)

func runArchiveIndexCommand(ctx context.Context, args []string, out, diagnostics io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "lev-index" {
		return false, nil
	}
	usage := func() {
		fmt.Fprintln(diagnostics, "Usage: ex-sbom lev-index build --archive DIR --as-of YYYY-MM-DD --output NEW_DIR [--reservations FILE]")
	}
	if len(args) < 2 || args[1] != "build" {
		usage()
		return true, errors.New("expected lev-index build")
	}
	flags := flag.NewFlagSet("lev-index build", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	flags.Usage = usage
	source := flags.String("archive", "", "directory containing official EPSS day files")
	cutoff := flags.String("as-of", "", "inclusive UTC archive cutoff")
	output := flags.String("output", "", "new sealed snapshot directory")
	reservations := flags.String("reservations", "", "optional CVE reservations JSON")
	if err := flags.Parse(args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return true, nil
		}
		return true, err
	}
	if flags.NArg() != 0 || *source == "" || *cutoff == "" || *output == "" {
		usage()
		return true, errors.New("archive, as-of and output are required")
	}
	if err := first.BuildArchiveIndex(ctx, *source, *reservations, *cutoff, *output); err != nil {
		return true, err
	}
	fmt.Fprintln(out, *output)
	return true, nil
}
