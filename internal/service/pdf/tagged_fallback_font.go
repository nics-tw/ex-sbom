// SPDX-License-Identifier: MIT

//go:build taggedpdf && ((darwin && !ios && arm64) || (linux && !android && (arm64 || amd64)) || (windows && amd64))

package pdf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
	"unicode/utf8"
)

const maxFallbackGlyphs = 1<<16 - 2 // One glyph index is reserved for .notdef.

// buildFallbackFont copies the template's boxed question mark to a distinct glyph
// for each missing scalar so the PDF can map every glyph back to its original text.
func buildFallbackFont(template []byte, missing []rune) ([]byte, error) {
	tables, err := fallbackFontTables(template)
	if err != nil {
		return nil, err
	}
	be := binary.BigEndian
	head, hhea, hmtx, maxp := tables["head"], tables["hhea"], tables["hmtx"], tables["maxp"]
	loca, glyf, post := tables["loca"], tables["glyf"], tables["post"]
	if len(head) != 54 || len(hhea) != 36 || len(hmtx) != 6 || len(maxp) != 32 || len(loca) != 6 || len(post) != 32 || tables["cmap"] == nil ||
		be.Uint16(head[50:]) != 0 || be.Uint16(hhea[34:]) != 1 || be.Uint16(maxp[4:]) != 2 || be.Uint16(loca) != 0 || be.Uint32(post) != 0x00030000 {
		return nil, errors.New("unexpected fallback font template layout")
	}
	notdefEnd, boxEnd := 2*int(be.Uint16(loca[2:])), 2*int(be.Uint16(loca[4:]))
	if notdefEnd < 10 || boxEnd-notdefEnd < 10 || boxEnd > len(glyf) || be.Uint16(glyf[notdefEnd:]) > 32767 {
		return nil, errors.New("invalid fallback font glyph outlines")
	}

	points := slices.Clone(missing)
	slices.Sort(points)
	points = slices.Compact(points)
	if len(points) > maxFallbackGlyphs {
		return nil, fmt.Errorf("fallback font has %d characters, maximum %d", len(points), maxFallbackGlyphs)
	}
	for _, point := range points {
		if !utf8.ValidRune(point) {
			return nil, fmt.Errorf("invalid fallback font Unicode scalar %U", point)
		}
	}

	glyphCount := 1 + len(points)
	box := glyf[notdefEnd:boxEnd]
	newGlyf := make([]byte, notdefEnd+len(box)*len(points))
	copy(newGlyf, glyf[:notdefEnd])
	newLoca := make([]byte, 4*(glyphCount+1))
	newHmtx := make([]byte, 4+2*len(points))
	copy(newHmtx, hmtx[:4])
	for i := range points {
		offset := notdefEnd + i*len(box)
		copy(newGlyf[offset:], box)
		be.PutUint32(newLoca[4*(i+1):], uint32(offset))
		copy(newHmtx[4+2*i:], hmtx[4:])
	}
	be.PutUint32(newLoca[4*glyphCount:], uint32(len(newGlyf)))

	tables["glyf"], tables["loca"], tables["hmtx"] = newGlyf, newLoca, newHmtx
	tables["head"], tables["maxp"] = slices.Clone(head), slices.Clone(maxp)
	be.PutUint16(tables["head"][50:], 1) // 32-bit glyph offsets in loca.
	be.PutUint16(tables["maxp"][4:], uint16(glyphCount))
	tables["cmap"] = fallbackCmap(points)
	return assembleFallbackFont(template[:12], tables), nil
}

func fallbackFontTables(template []byte) (map[string][]byte, error) {
	const headerSize, recordSize = 12, 16
	be := binary.BigEndian
	if len(template) < headerSize || be.Uint32(template[:4]) != 0x00010000 {
		return nil, errors.New("invalid fallback TrueType font header")
	}
	tableCount := int(be.Uint16(template[4:6]))
	directorySize := headerSize + recordSize*tableCount
	if directorySize > len(template) {
		return nil, errors.New("truncated fallback TrueType font directory")
	}
	tables := make(map[string][]byte, tableCount)
	for i := range tableCount {
		record := headerSize + i*recordSize
		tag := string(template[record : record+4])
		offset := uint64(be.Uint32(template[record+8 : record+12]))
		length := uint64(be.Uint32(template[record+12 : record+16]))
		if offset < uint64(directorySize) || offset+length > uint64(len(template)) {
			return nil, fmt.Errorf("invalid fallback font table %q", tag)
		}
		if _, exists := tables[tag]; exists {
			return nil, fmt.Errorf("duplicate fallback font table %q", tag)
		}
		tables[tag] = template[offset : offset+length]
	}
	return tables, nil
}

func assembleFallbackFont(header []byte, tables map[string][]byte) []byte {
	const headerSize, recordSize = 12, 16
	be := binary.BigEndian
	directorySize := headerSize + recordSize*len(tables)
	fontSize := directorySize
	for _, table := range tables {
		fontSize += (len(table) + 3) &^ 3
	}
	font := make([]byte, directorySize, fontSize)
	copy(font, header)
	headOffset := 0
	for i, tag := range slices.Sorted(maps.Keys(tables)) {
		record := headerSize + i*recordSize
		table := tables[tag]
		tableOffset := len(font)
		font = append(font, table...)
		if tag == "head" {
			headOffset = tableOffset
			clear(font[headOffset+8 : headOffset+12])
		}
		var padding [3]byte
		font = append(font, padding[:(4-len(table)%4)%4]...)
		copy(font[record:record+4], tag)
		be.PutUint32(font[record+4:record+8], trueTypeChecksum(font[tableOffset:]))
		be.PutUint32(font[record+8:record+12], uint32(tableOffset))
		be.PutUint32(font[record+12:record+16], uint32(len(table)))
	}
	const trueTypeChecksumTarget = 0xB1B0AFBA
	be.PutUint32(font[headOffset+8:headOffset+12], trueTypeChecksumTarget-trueTypeChecksum(font))
	return font
}

func fallbackCmap(points []rune) []byte {
	const format12Offset, format12Header, groupSize = 20, 16, 12
	table := make([]byte, format12Offset+format12Header+groupSize*len(points))
	be := binary.BigEndian
	be.PutUint16(table[2:], 2)
	be.PutUint16(table[6:], 4) // Unicode full repertoire
	be.PutUint32(table[8:], format12Offset)
	be.PutUint16(table[12:], 3)  // Windows
	be.PutUint16(table[14:], 10) // Windows full Unicode repertoire
	be.PutUint32(table[16:], format12Offset)
	be.PutUint16(table[20:], 12)
	headerSize := format12Offset + format12Header
	groups := 0
	for i, point := range points {
		offset := headerSize + groups*groupSize
		if i > 0 && point == points[i-1]+1 {
			be.PutUint32(table[offset-groupSize+4:], uint32(point))
			continue
		}
		be.PutUint32(table[offset:], uint32(point))
		be.PutUint32(table[offset+4:], uint32(point))
		be.PutUint32(table[offset+8:], uint32(i+1))
		groups++
	}
	table = table[:headerSize+groups*groupSize]
	be.PutUint32(table[24:], uint32(len(table)-format12Offset))
	be.PutUint32(table[32:], uint32(groups))
	return table
}

func trueTypeChecksum(font []byte) uint32 {
	var sum uint32
	for offset := 0; offset < len(font); offset += 4 {
		sum += binary.BigEndian.Uint32(font[offset : offset+4])
	}
	return sum
}
