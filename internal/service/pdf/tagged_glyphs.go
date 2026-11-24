// SPDX-License-Identifier: MIT

//go:build taggedpdf && ((darwin && !ios && arm64) || (linux && !android && (arm64 || amd64)) || (windows && amd64))

package pdf

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/image/font/sfnt"
)

//go:embed fonts/tagged-fallback.ttf
var taggedFallbackTemplate []byte

// prepareTaggedGlyphs converts control characters to visible codes, as the
// existing renderer does, and creates the report-specific fallback font.
func prepareTaggedGlyphs(report *taggedData, fontDir string) error {
	cjk, err := sfntFont(filepath.Join(fontDir, taggedCJKFont))
	if err != nil {
		return err
	}
	emoji, err := sfntFont(filepath.Join(fontDir, taggedEmojiFont))
	if err != nil {
		return err
	}

	var buffer sfnt.Buffer
	seen := make(map[rune]struct{})
	var missing []rune
	visit := func(value *string) {
		var clean strings.Builder
		for _, point := range *value {
			// Keep intentional line breaks and tabs in advisory prose. The
			// surrounding renderer will handle their layout.
			if point == '\n' || point == '\r' || point == '\t' {
				clean.WriteRune(point)
				continue
			}
			if unicode.IsControl(point) || unicode.Is(unicode.Cf, point) {
				fmt.Fprintf(&clean, "[U+%04X]", point)
				continue
			}
			clean.WriteRune(point)
			if _, ok := seen[point]; ok {
				continue
			}
			seen[point] = struct{}{}
			cjkIndex, cjkErr := cjk.GlyphIndex(&buffer, point)
			emojiIndex, emojiErr := emoji.GlyphIndex(&buffer, point)
			if (cjkErr != nil || cjkIndex == 0) && (emojiErr != nil || emojiIndex == 0) {
				missing = append(missing, point)
			}
		}
		*value = clean.String()
	}
	fields := func(items []taggedField) {
		for i := range items {
			visit(&items[i].Label)
			visit(&items[i].Value)
		}
	}
	visit(&report.Title)
	visit(&report.Warning)
	visit(&report.EmptyRemediation)
	fields(report.Metadata)
	fields(report.Evidence)
	fields(report.Summary)
	for i := range report.Actions {
		visit(&report.Actions[i].Title)
		fields(report.Actions[i].Fields)
	}
	for i := range report.Components {
		visit(&report.Components[i].Name)
		visit(&report.Components[i].Version)
		visit(&report.Components[i].Scope)
	}
	visit(&report.OrderNote)
	for i := range report.OrderHeaders {
		visit(&report.OrderHeaders[i])
	}
	for _, row := range report.OrderRows {
		for i := range row.Cells {
			visit(&row.Cells[i])
		}
	}
	for i := range report.Findings {
		finding := &report.Findings[i]
		visit(&finding.Title)
		visit(&finding.Component.Value)
		visit(&finding.Version.Value)
		visit(&finding.Summary.Value)
		fields(finding.Fields)
		visit(&finding.Details.Value)
	}
	fontFile := filepath.Join(fontDir, taggedFallbackFont)
	if len(missing) == 0 {
		return os.WriteFile(fontFile, taggedFallbackTemplate, 0600)
	}
	report.HasMissingGlyphs = true
	font, err := buildFallbackFont(taggedFallbackTemplate, missing)
	if err != nil {
		return err
	}
	return os.WriteFile(fontFile, font, 0600)
}

func sfntFont(path string) (*sfnt.Font, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return sfnt.Parse(data)
}
