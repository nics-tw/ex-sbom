// SPDX-License-Identifier: MIT

//go:build taggedpdf && ((darwin && !ios && arm64) || (linux && !android && (arm64 || amd64)) || (windows && amd64))

package pdf

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

//go:embed report.typ
var taggedTemplate []byte

const (
	taggedAssetDir     = "bundle/" + runtime.GOOS + "_" + runtime.GOARCH + "/"
	taggedCJKFont      = "NotoSansCJKtc-Regular.otf"
	taggedCJKBoldFont  = "NotoSansCJKtc-Bold.otf"
	taggedEmojiFont    = "NotoEmoji.ttf"
	taggedFallbackFont = "fallback.ttf"
	taggedStderrLimit  = 4096
)

var taggedRenderSlot = make(chan struct{}, 1)

func GenerateContext(ctx context.Context, w io.Writer, report Report) error {
	timeout := 30 * time.Second
	if value := os.Getenv("EX_SBOM_PDF_TIMEOUT"); value != "" {
		var err error
		timeout, err = time.ParseDuration(value)
		if err != nil || timeout <= 0 {
			return fmt.Errorf("EX_SBOM_PDF_TIMEOUT must be a positive duration, such as 60s")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case taggedRenderSlot <- struct{}{}:
		defer func() { <-taggedRenderSlot }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	typst, err := taggedExecutable()
	if err != nil {
		return fmt.Errorf("prepare cached Typst (set EX_SBOM_PDF_CACHE_DIR to a private executable directory): %w", err)
	}
	workspaceRoot := taggedWorkspaceRoot(typst)
	dir, err := os.MkdirTemp(workspaceRoot, "ex-sbom-tagged-pdf-")
	if err != nil {
		if workspaceRoot != "" {
			return fmt.Errorf("create tagged report workspace: %w: %w", ErrCacheUnavailable, err)
		}
		return fmt.Errorf("create tagged report workspace: %w", err)
	}
	defer os.RemoveAll(dir)

	fontDir := filepath.Join(dir, "fonts")
	if err := os.Mkdir(fontDir, 0700); err != nil {
		return fmt.Errorf("create tagged report font directory: %w", err)
	}
	for _, font := range []string{taggedCJKFont, taggedCJKBoldFont, taggedEmojiFont} {
		if err := ctx.Err(); err != nil {
			return err
		}
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
	configureTaggedCommand(cmd, dir)
	var diagnostics taggedStderr
	cmd.Stderr = &diagnostics
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("compile tagged PDF: %w", ctx.Err())
		}
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("%w: execute cached Typst (set EX_SBOM_PDF_CACHE_DIR to a private executable directory): %w", ErrCacheUnavailable, err)
		}
		if detail := strings.TrimSpace(string(diagnostics)); detail != "" {
			return fmt.Errorf("compile tagged PDF: %w: %q", err, detail)
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

type taggedStderr []byte

func (s *taggedStderr) Write(p []byte) (int, error) {
	*s = append(*s, p[:min(len(p), taggedStderrLimit-len(*s))]...)
	return len(p), nil
}

func unpackTaggedAsset(name, target string, mode os.FileMode) (err error) {
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
	}()
	return copyTaggedAsset(name, out)
}

func copyTaggedAsset(name string, target io.Writer) error {
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

	_, err = io.Copy(target, source)
	return err
}
