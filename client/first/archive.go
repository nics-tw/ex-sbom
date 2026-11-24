// SPDX-License-Identifier: MIT

package first

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ex-sbom/client/cisa"
)

// FirstArchiveDay is the start of EPSS v1's public daily archive.
const FirstArchiveDay = "2021-04-14"

const (
	maxArchiveBytes = 64 << 20
	maxArchiveRow   = 4 << 10
	maxCachedDays   = 4096
	maxCachedRows   = 262144
)

type HistoricalLEV struct {
	Score float64
	First string
	AsOf  string
	// Partial marks a lower bound calculated from the available windows.
	Partial bool
}

type archiveFinding struct {
	first   string
	next    string
	scores  []TimeSeries
	partial bool
}

type archiveScore struct {
	score   float64
	found   bool
	unknown bool
}

type cachedDay struct {
	file    os.FileInfo
	rows    map[string]archiveScore
	warning error
}

var archiveCache struct {
	sync.Mutex
	days map[string]cachedDay
	rows int
}

// ArchiveLEV evaluates several CVEs in one pass over the official daily archives.
func ArchiveLEV(dir, firstDay, asOf string, cves []string) (map[string]HistoricalLEV, error) {
	return ArchiveLEVWithReservations(dir, firstDay, asOf, cves, nil)
}

// ArchiveLEVWithReservations accepts known first possible score dates.
func ArchiveLEVWithReservations(dir, firstDay, asOf string, cves []string, reserved map[string]string) (map[string]HistoricalLEV, error) {
	return ArchiveLEVContext(context.Background(), dir, firstDay, asOf, cves, reserved)
}

// ArchiveLEVContext returns only results with a verified first score date.
// Missing window scores and cancellation after that date yield lower bounds.
func ArchiveLEVContext(ctx context.Context, dir, firstDay, asOf string, cves []string, reserved map[string]string) (map[string]HistoricalLEV, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	start, startErr := time.Parse(time.DateOnly, firstDay)
	end, endErr := time.Parse(time.DateOnly, asOf)
	if startErr != nil || endErr != nil || start.After(end) {
		return nil, fmt.Errorf("invalid EPSS archive period")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	pending := make(map[string]*archiveFinding, len(cves))
	earliest := make(map[string]string)
	var firstError error
	for _, cve := range cves {
		pending[cve] = &archiveFinding{}
		if date := reserved[cve]; date != "" {
			if _, err := time.Parse(time.DateOnly, date); err == nil {
				if date > asOf {
					delete(pending, cve)
				} else {
					earliest[cve] = date
				}
			} else if firstError == nil {
				firstError = fmt.Errorf("invalid reservation date for %s", cve)
			}
		}
	}

	for day := start; len(pending) != 0 && !day.After(end) && ctx.Err() == nil; day = day.AddDate(0, 0, 1) {
		date := day.Format(time.DateOnly)
		wanted := make(map[string]*archiveFinding)
		for cve, entry := range pending {
			if (entry.first == "" && date >= earliest[cve]) || entry.next == date {
				wanted[cve] = entry
			}
		}
		if len(wanted) == 0 {
			continue
		}
		rows, err := archiveDay(ctx, filepath.Join(dir, "epss_scores-"+date+".csv.gz"), date, wanted)
		if err != nil && firstError == nil && !errors.Is(err, os.ErrNotExist) && ctx.Err() == nil {
			firstError = fmt.Errorf("EPSS archive %s: %w", date, err)
		}
		for cve, finding := range wanted {
			row := rows[cve]
			if finding.first == "" {
				if rows == nil || row.unknown {
					delete(pending, cve)
					continue
				}
				if !row.found {
					continue
				}
				finding.first = date
			}
			finding.next = day.AddDate(0, 0, 30).Format(time.DateOnly)
			if !row.found {
				finding.partial = true
				continue
			}
			finding.scores = append(finding.scores, TimeSeries{Date: date, EPSS: strconv.FormatFloat(row.score, 'g', -1, 64)})
		}
	}

	results := make(map[string]HistoricalLEV)
	for cve, finding := range pending {
		if finding.first == "" {
			continue
		}
		if score, valid := calculateAvailableLEV(finding.scores, finding.first, asOf); valid {
			results[cve] = HistoricalLEV{
				Score: score, First: finding.first, AsOf: asOf,
				Partial: finding.partial || finding.next <= asOf,
			}
		}
	}
	return results, errors.Join(firstError, ctx.Err())
}

func archiveDay(ctx context.Context, path, day string, wanted map[string]*archiveFinding) (map[string]archiveScore, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxArchiveBytes {
		return nil, fmt.Errorf("invalid EPSS archive file type or size")
	}
	if rows, warning := cachedArchiveRows(path, info, wanted); rows != nil {
		return rows, warning
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil || !sameArchive(fileInfo, info) {
		return nil, fmt.Errorf("EPSS archive file changed while opening")
	}
	rows, warning := readArchiveDay(ctx, file, day, wanted)
	if rows != nil {
		if final, err := file.Stat(); err != nil || !sameArchive(final, info) {
			return nil, fmt.Errorf("EPSS archive file changed while reading")
		}
		cacheArchiveRows(path, info, rows, warning)
	}
	return rows, warning
}

func cachedArchiveRows(path string, info os.FileInfo, wanted map[string]*archiveFinding) (map[string]archiveScore, error) {
	archiveCache.Lock()
	defer archiveCache.Unlock()
	day, ok := archiveCache.days[path]
	if !ok || !sameArchive(day.file, info) || len(day.rows) < len(wanted) {
		return nil, nil
	}
	rows := make(map[string]archiveScore, len(wanted))
	for cve := range wanted {
		row, exists := day.rows[cve]
		if !exists {
			return nil, nil
		}
		rows[cve] = row
	}
	return rows, day.warning
}

func cacheArchiveRows(path string, info os.FileInfo, rows map[string]archiveScore, warning error) {
	if len(rows) > maxCachedRows {
		return
	}
	archiveCache.Lock()
	defer archiveCache.Unlock()
	day, exists := archiveCache.days[path]
	if archiveCache.rows+len(rows) > maxCachedRows || (!exists && len(archiveCache.days) >= maxCachedDays) {
		clear(archiveCache.days)
		archiveCache.rows = 0
		day = cachedDay{}
	}
	if day.file == nil || !sameArchive(day.file, info) {
		archiveCache.rows -= len(day.rows)
		day = cachedDay{file: info, rows: make(map[string]archiveScore, len(rows))}
	}
	before := len(day.rows)
	for cve, row := range rows {
		day.rows[cve] = row
	}
	if warning != nil {
		day.warning = warning
	}
	if archiveCache.days == nil {
		archiveCache.days = make(map[string]cachedDay)
	}
	archiveCache.days[path] = day
	archiveCache.rows += len(day.rows) - before
}

func sameArchive(a, b os.FileInfo) bool {
	return a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && os.SameFile(a, b)
}

type archiveReader struct {
	context.Context
	io.Reader
}

func (r archiveReader) Read(p []byte) (int, error) {
	if err := r.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func readArchiveDay(ctx context.Context, file io.Reader, day string, wanted map[string]*archiveFinding) (map[string]archiveScore, error) {
	compressed := &io.LimitedReader{R: archiveReader{ctx, file}, N: maxArchiveBytes + 1}
	stream, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	limited := &io.LimitedReader{R: stream, N: maxArchiveBytes + 1}
	reader := bufio.NewReaderSize(limited, maxArchiveRow)
	header, err := archiveCSVHeader(ctx, reader)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(header[0], "#") {
		if len(header) != 2 || !strings.HasPrefix(header[0], "#model_version:") || !strings.HasPrefix(header[1], "score_date:"+day+"T") {
			return nil, fmt.Errorf("invalid model or score date")
		}
		header, err = archiveCSVHeader(ctx, reader)
		if err != nil {
			return nil, err
		}
	}
	hasPercentile := len(header) == 3 && header[2] == "percentile"
	if (len(header) != 2 && !hasPercentile) || header[0] != "cve" || header[1] != "epss" {
		return nil, fmt.Errorf("invalid EPSS CSV header")
	}
	rows := make(map[string]archiveScore, len(wanted))
	badRows, uncertain := 0, false
	for {
		line, overlong, err := nextArchiveLine(ctx, reader)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if line == "" && !overlong {
			continue
		}
		var id, raw string
		var valid bool
		if overlong {
			id = strings.Trim(line, "\"")
		} else {
			id, raw, valid = archiveCSVScore(line, hasPercentile)
		}
		if !cisa.IsCVE(id) {
			badRows++
			uncertain = true
			continue
		}
		var score float64
		if valid {
			score, valid = ParseProbability(raw)
		}
		if _, duplicate := rows[id]; duplicate {
			valid = false
		}
		if !valid {
			badRows++
		}
		if _, needed := wanted[id]; needed {
			rows[strings.Clone(id)] = archiveScore{score: score, found: valid, unknown: !valid}
		}
	}
	if limited.N == 0 || compressed.N == 0 {
		return nil, fmt.Errorf("EPSS archive exceeds compressed or decompressed size limit")
	}
	for cve := range wanted {
		if _, seen := rows[cve]; !seen {
			rows[cve] = archiveScore{unknown: uncertain}
		}
	}
	if badRows > 0 {
		return rows, fmt.Errorf("skipped %d invalid or duplicate EPSS CSV rows", badRows)
	}
	return rows, nil
}

func archiveCSVHeader(ctx context.Context, reader *bufio.Reader) ([]string, error) {
	for {
		line, overlong, err := nextArchiveLine(ctx, reader)
		if err != nil {
			return nil, fmt.Errorf("read EPSS CSV header: %w", err)
		}
		if overlong {
			return nil, fmt.Errorf("EPSS CSV header exceeds row size limit")
		}
		if line != "" {
			return csv.NewReader(strings.NewReader(line)).Read()
		}
	}
}

// nextArchiveLine discards overlong rows in bounded fragments, keeping the ID
// when it fits in the first fragment.
func nextArchiveLine(ctx context.Context, reader *bufio.Reader) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	line, err := reader.ReadSlice('\n')
	if err != bufio.ErrBufferFull {
		if err == io.EOF && len(line) > 0 {
			err = nil
		}
		return strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"), false, err
	}
	var id string
	if comma := bytes.IndexByte(line, ','); comma >= 0 {
		id = string(line[:comma])
	}
	for err == bufio.ErrBufferFull {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		_, err = reader.ReadSlice('\n')
	}
	if err == io.EOF {
		err = nil
	}
	return id, true, err
}

func archiveCSVScore(line string, hasPercentile bool) (string, string, bool) {
	if strings.ContainsRune(line, '"') {
		reader := csv.NewReader(strings.NewReader(line))
		if hasPercentile {
			reader.FieldsPerRecord = 3
		} else {
			reader.FieldsPerRecord = 2
		}
		row, err := reader.Read()
		if len(row) > 1 {
			return row[0], row[1], err == nil
		}
		if len(row) == 1 {
			return row[0], "", false
		}
	}
	id, remainder, comma := strings.Cut(line, ",")
	score, percentile, extra := strings.Cut(remainder, ",")
	return id, score, comma && extra == hasPercentile && !strings.ContainsAny(percentile, ",\"") && !strings.ContainsRune(score, '"')
}
