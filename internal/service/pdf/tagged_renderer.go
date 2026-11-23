// SPDX-License-Identifier: MIT

//go:build taggedpdf && ((darwin && !ios && arm64) || (linux && !android && (arm64 || amd64)))

package pdf

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

//go:embed report.typ
var taggedTemplate []byte

const (
	taggedAssetDir     = "bundle/" + runtime.GOOS + "_" + runtime.GOARCH + "/"
	taggedCJKFont      = "NotoSansCJKtc-Regular.otf"
	taggedEmojiFont    = "NotoEmoji.ttf"
	taggedFallbackFont = "fallback.ttf"
)

func Generate(w io.Writer, report Report) error {
	dir, err := os.MkdirTemp("", "ex-sbom-tagged-pdf-")
	if err != nil {
		return fmt.Errorf("create tagged report workspace: %w", err)
	}
	defer os.RemoveAll(dir)

	fontDir := filepath.Join(dir, "fonts")
	if err := os.Mkdir(fontDir, 0700); err != nil {
		return fmt.Errorf("create tagged report font directory: %w", err)
	}
	for _, font := range []string{taggedCJKFont, taggedEmojiFont} {
		if err := unpackTaggedAsset(font, filepath.Join(fontDir, font), 0600); err != nil {
			return fmt.Errorf("unpack tagged report font %s: %w", font, err)
		}
	}

	model := buildTaggedData(report)
	if err := prepareTaggedGlyphs(&model, fontDir); err != nil {
		return fmt.Errorf("prepare tagged report glyphs: %w", err)
	}
	data, err := json.Marshal(model)
	if err != nil {
		return fmt.Errorf("encode tagged report data: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), data, 0600); err != nil {
		return fmt.Errorf("write tagged report data: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.typ"), taggedTemplate, 0600); err != nil {
		return fmt.Errorf("write tagged report template: %w", err)
	}

	typst := filepath.Join(dir, "typst")
	if err := unpackTaggedAsset("typst", typst, 0700); err != nil {
		return fmt.Errorf("unpack tagged report renderer: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, typst, "compile",
		"--pdf-standard", "ua-1",
		"--root", dir,
		"--ignore-system-fonts",
		"--ignore-embedded-fonts",
		"--font-path", fontDir,
		"report.typ", "report.pdf",
	)
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + dir, "TMPDIR=" + dir, "PATH="}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return fmt.Errorf("compile tagged PDF: %w", err)
	}

	output, err := os.ReadFile(filepath.Join(dir, "report.pdf"))
	if err != nil {
		return fmt.Errorf("read tagged PDF: %w", err)
	}
	if !bytes.HasPrefix(output, []byte("%PDF-")) {
		return fmt.Errorf("tagged renderer did not create PDF")
	}
	_, err = io.Copy(w, bytes.NewReader(output))
	return err
}

func unpackTaggedAsset(name, target string, mode os.FileMode) (err error) {
	bundle, err := taggedAssets.Open(taggedAssetDir + name + ".gz")
	if err != nil {
		return err
	}
	defer bundle.Close()
	source, err := gzip.NewReader(bundle)
	if err != nil {
		return err
	}
	defer source.Close()

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
	}()
	_, err = io.Copy(out, source)
	return err
}
