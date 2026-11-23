// SPDX-License-Identifier: MIT

package first

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FirstArchiveDay is the start of EPSS v1's public daily archive.
const FirstArchiveDay = "2021-04-14"

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

// ArchiveLEV evaluates several CVEs in one pass over official daily archives.
// A missing file before the first score prevents establishing the window
// anchor. A missing window after that anchor yields a lower bound.
func ArchiveLEV(dir, firstDay, asOf string, cves []string) (map[string]HistoricalLEV, error) {
	return ArchiveLEVWithReservations(dir, firstDay, asOf, cves, nil)
}

// ArchiveLEVWithReservations uses known CVE reservation dates as lower
// bounds on when a score could have first been assigned.
func ArchiveLEVWithReservations(dir, firstDay, asOf string, cves []string, reserved map[string]string) (map[string]HistoricalLEV, error) {
	start, startErr := time.Parse(time.DateOnly, firstDay)
	end, endErr := time.Parse(time.DateOnly, asOf)
	if startErr != nil || endErr != nil || start.After(end) {
		return nil, fmt.Errorf("invalid EPSS archive period")
	}
	pending := make(map[string]*archiveFinding, len(cves))
	for _, cve := range cves {
		if earliest := reserved[cve]; earliest != "" {
			if _, err := time.Parse(time.DateOnly, earliest); err != nil {
				return nil, fmt.Errorf("invalid CVE reservation date for %s", cve)
			}
		}
		pending[cve] = &archiveFinding{}
	}
	var firstError error
	for day := start; !day.After(end); day = day.AddDate(0, 0, 1) {
		date := day.Format(time.DateOnly)
		wanted := make(map[string]*archiveFinding)
		for cve, entry := range pending {
			if (entry.first == "" && date >= reserved[cve]) || entry.next == date {
				wanted[cve] = entry
			}
		}
		if len(wanted) == 0 {
			continue
		}
		rows, err := archiveDay(dir, date, wanted)
		if err != nil {
			if firstError == nil && !os.IsNotExist(err) {
				firstError = fmt.Errorf("EPSS archive %s: %w", date, err)
			}
		}
		for cve, finding := range wanted {
			score, found := rows[cve]
			if !found {
				if err != nil && finding.first == "" {
					delete(pending, cve)
					continue
				}
				if finding.first != "" {
					finding.partial = true
					finding.next = day.AddDate(0, 0, 30).Format(time.DateOnly)
				}
				continue
			}
			if finding.first == "" {
				finding.first = date
			}
			finding.scores = append(finding.scores, TimeSeries{Date: date, EPSS: score})
			finding.next = day.AddDate(0, 0, 30).Format(time.DateOnly)
		}
	}
	results := make(map[string]HistoricalLEV)
	for cve, finding := range pending {
		if finding.first == "" {
			continue
		}
		if score, valid := calculateAvailableLEV(finding.scores, finding.first, asOf); valid {
			results[cve] = HistoricalLEV{Score: score, First: finding.first, AsOf: asOf, Partial: finding.partial}
		}
	}
	return results, firstError
}

func archiveDay(dir, day string, wanted map[string]*archiveFinding) (map[string]string, error) {
	file, err := os.Open(filepath.Join(dir, "epss_scores-"+day+".csv.gz"))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stream, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	reader := csv.NewReader(stream)
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(header[0], "#") {
		if len(header) != 2 || !strings.HasPrefix(header[0], "#model_version:") ||
			!strings.HasPrefix(header[1], "score_date:"+day+"T") {
			return nil, fmt.Errorf("invalid model or score date")
		}
		header, err = reader.Read()
		if err != nil {
			return nil, err
		}
	}
	if !validArchiveHeader(header) {
		return nil, fmt.Errorf("invalid EPSS CSV header")
	}
	reader.FieldsPerRecord = len(header)
	reader.ReuseRecord = true
	results := make(map[string]string)
	for {
		row, err := reader.Read()
		if err == io.EOF {
			return results, nil
		}
		if err != nil {
			return nil, err
		}
		if _, needed := wanted[row[0]]; !needed {
			continue
		}
		if _, duplicate := results[row[0]]; duplicate {
			return nil, fmt.Errorf("duplicate CVE %s", row[0])
		}
		if _, valid := ParseProbability(row[1]); !valid {
			return nil, fmt.Errorf("invalid EPSS for %s", row[0])
		}
		results[row[0]] = row[1]
	}
}

func validArchiveHeader(header []string) bool {
	columns := strings.Join(header, ",")
	return columns == "cve,epss" || columns == "cve,epss,percentile"
}
