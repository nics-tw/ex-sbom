// SPDX-License-Identifier: MIT

package first

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/marcboeker/go-duckdb"
)

const archiveIndexDatabaseLimit = 256 << 20

type indexedFinding struct {
	first       int
	next        int
	logSurvival float64
	partial     bool
}

// BuildArchiveIndex publishes a new sealed day/archive/index snapshot. It reads
// the source directory and reservation file without changing them. The
// output's parent directory must be controlled by the service account.
func BuildArchiveIndex(ctx context.Context, source, reservations, asOf, output string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dates, err := archiveIndexDates(asOf)
	if err != nil {
		return err
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return err
	}
	if info, err := os.Stat(source); err != nil || !info.IsDir() {
		return errors.New("EPSS archive must be an existing directory")
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("output %s: %w", output, os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staging, err := makeArchiveStaging(filepath.Dir(output))
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = removeArchiveStaging(staging)
		}
	}()
	manifest := archiveIndexManifest{Version: archiveIndexVersion, Method: LEVMethod, FirstDay: FirstArchiveDay, AsOf: asOf, Days: make([]*archiveIndexFile, len(dates))}
	sources := make([]archiveSourceState, len(dates))
	for i, day := range dates {
		name := archiveDayName(day)
		sources[i], err = captureArchiveSource(filepath.Join(source, name))
		if err != nil {
			return fmt.Errorf("inspect EPSS archive %s: %w", day, err)
		}
	}
	var reserved map[string]string
	var reservationState archiveSourceState
	if reservations != "" {
		reservations, err = filepath.Abs(reservations)
		if err != nil {
			return err
		}
		sealedFile := filepath.Join(staging, ArchiveIndexReservations)
		reservationState, err = captureArchiveSource(reservations)
		if err != nil || reservationState.info == nil {
			return fmt.Errorf("invalid CVE reservation source %q", reservations)
		}
		manifest.Reservations, err = stageArchiveFile(ctx, reservations, sealedFile, reservationState, maxReservationBytes, nil)
		if err != nil {
			return err
		}
		reserved, err = ReadCVEReservations(ctx, sealedFile, nil)
		if err != nil {
			slog.Warn("CVE reservation data is incomplete", "error", err)
		}
	}

	rows := make(map[string]archiveScore)
	findings := make(map[string]indexedFinding)
	invalidFirst := make(map[string]struct{})
	firstEligible := initialArchiveDays(dates[0], reserved)
	lastUnknown := -1
	for i, day := range dates {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := archiveDayName(day)
		usable, uncertain := false, false
		clear(rows)
		if state := sources[i]; state.info != nil && state.info.Size() <= maxArchiveBytes {
			var dayErr error
			manifest.Days[i], err = stageArchiveFile(ctx, filepath.Join(source, name), filepath.Join(staging, name), state, maxArchiveBytes,
				func(reader io.Reader) {
					usable, uncertain, dayErr = readArchiveScores(ctx, reader, day, rows, func(cve string) bool {
						if known, ok := findings[cve]; ok {
							return known.next <= i && (i-known.next)%levWindowDays == 0
						}
						boundary := firstEligible[cve]
						_, failed := invalidFirst[cve]
						return boundary <= i && boundary > lastUnknown && !failed
					})
				})
			if err != nil {
				return fmt.Errorf("stage EPSS archive %s: %w", day, err)
			}
			if dayErr != nil {
				slog.Warn("EPSS archive day contains unusable data", "day", day, "error", dayErr)
			}
		} else if state.info != nil {
			slog.Warn("EPSS archive day exceeds its compressed size limit", "day", day)
		}
		if !usable {
			lastUnknown = i
			continue
		}
		advanceIndexedFindings(findings, invalidFirst, rows, i, time.Duration(len(dates)-i)*24*time.Hour)
		if uncertain {
			lastUnknown = i
		}
	}
	indexPath := filepath.Join(staging, archiveIndexDBName)
	if err := writeArchiveIndex(ctx, indexPath, &manifest, dates, findings); err != nil {
		return err
	}
	manifest.Index, err = finishIndexFile(ctx, indexPath)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if len(encoded) > archiveIndexManifestLimit {
		return errors.New("archive snapshot manifest exceeds its size limit")
	}
	manifestPath := filepath.Join(staging, archiveIndexManifestName)
	if err := os.WriteFile(manifestPath, encoded, 0600); err != nil {
		return err
	}
	if err := sealArchiveFile(manifestPath); err != nil {
		return err
	}
	for i, day := range dates {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyArchiveSource(filepath.Join(source, archiveDayName(day)), sources[i]); err != nil {
			return err
		}
	}
	if reservations != "" {
		if err := verifyArchiveSource(reservations, reservationState); err != nil {
			return err
		}
	}
	if err := sealAndPublishArchiveDirectory(ctx, staging, output); err != nil {
		if _, exists := os.Lstat(output); exists == nil {
			return fmt.Errorf("output %s: %w", output, os.ErrExist)
		}
		return err
	}
	published = true
	return nil
}

func initialArchiveDays(first string, reserved map[string]string) map[string]int {
	start, _ := time.Parse(time.DateOnly, first)
	days := make(map[string]int, len(reserved))
	for cve, date := range reserved {
		reservedDay, err := time.Parse(time.DateOnly, date)
		if err == nil && reservedDay.After(start) {
			days[cve] = int(reservedDay.Sub(start) / (24 * time.Hour))
		}
	}
	return days
}

func advanceIndexedFindings(findings map[string]indexedFinding, invalidFirst map[string]struct{}, rows map[string]archiveScore, day int, remaining time.Duration) {
	for cve, row := range rows {
		finding, known := findings[cve]
		if !known {
			if row.unknown {
				invalidFirst[cve] = struct{}{}
				continue
			}
			finding.first, finding.next = day, day
		}
		if finding.next < day {
			finding.partial = true
		}
		// Day eligibility is decided by readArchiveScores. Only a scheduled
		// observation can reach this point for an established CVE.
		if row.found {
			finding.logSurvival += levWindowSurvival(row.score, remaining)
		} else {
			finding.partial = true
		}
		finding.next = day + levWindowDays
		findings[cve] = finding
	}
}

type archiveSourceState struct {
	info     os.FileInfo
	identity string
}

func captureArchiveSource(path string) (archiveSourceState, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return archiveSourceState{}, nil
	}
	if err != nil {
		return archiveSourceState{}, err
	}
	if !info.Mode().IsRegular() {
		return archiveSourceState{}, fmt.Errorf("%s must be a regular file", filepath.Base(path))
	}
	identity, err := archiveIndexIdentity(path)
	return archiveSourceState{info: info, identity: identity}, err
}

func verifyArchiveSource(path string, prior archiveSourceState) error {
	current, err := captureArchiveSource(path)
	if err != nil {
		return err
	}
	if !sameArchiveSources(current, prior) {
		return fmt.Errorf("archive source changed: %s", filepath.Base(path))
	}
	return nil
}

func sameArchiveSources(a, b archiveSourceState) bool {
	if a.info == nil || b.info == nil {
		return a.info == nil && b.info == nil
	}
	return a.identity == b.identity && sameArchive(a.info, b.info)
}

func stageArchiveFile(ctx context.Context, path, target string, expected archiveSourceState, maxBytes int64, consume func(io.Reader)) (*archiveIndexFile, error) {
	if err := verifyArchiveSource(path, expected); err != nil {
		return nil, err
	}
	if expected.info.Size() > maxBytes {
		return nil, fmt.Errorf("archive source %s exceeds its size limit", filepath.Base(path))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !sameArchive(opened, expected.info) {
		return nil, errors.New("archive source changed while opening")
	}
	staged, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: archiveReader{ctx, file}, N: maxBytes + 1}
	hash := sha256.New()
	reader := io.TeeReader(limited, io.MultiWriter(staged, hash))
	if consume != nil {
		consume(reader)
	}
	_, err = io.Copy(io.Discard, reader)
	if err = errors.Join(err, staged.Close()); err != nil {
		return nil, err
	}
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if limited.N == 0 || info.Size() != expected.info.Size() {
		return nil, errors.New("archive source size changed or exceeded its limit")
	}
	if err := verifyArchiveSource(path, expected); err != nil {
		return nil, err
	}
	if err := sealArchiveFile(target); err != nil {
		return nil, err
	}
	identity, err := archiveIndexIdentity(target)
	if err != nil {
		return nil, err
	}
	return &archiveIndexFile{SHA256: hex.EncodeToString(hash.Sum(nil)), Identity: identity}, nil
}

func writeArchiveIndex(ctx context.Context, path string, manifest *archiveIndexManifest, dates []string, findings map[string]indexedFinding) error {
	db, err := openArchiveIndex(path, false)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "CREATE TABLE lev (cve VARCHAR, first_score VARCHAR, score DOUBLE, partial BOOLEAN)"); err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	ids := make([]string, 0, len(findings))
	for id := range findings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if err := conn.Raw(func(raw any) (err error) {
		appender, err := duckdb.NewAppenderFromConn(raw.(driver.Conn), "", "lev")
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, appender.Close()) }()
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			finding := findings[id]
			partial := finding.partial || finding.next < len(dates)
			if err := appender.AppendRow(id, dates[finding.first], levFromSurvival(finding.logSurvival), partial); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "CREATE UNIQUE INDEX lev_cve ON lev(cve)"); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "CREATE TABLE snapshot (id INT PRIMARY KEY, fingerprint VARCHAR)"); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "INSERT INTO snapshot VALUES (1, ?)", manifest.sourceFingerprint()); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "CHECKPOINT"); err != nil {
		return err
	}
	if err := conn.Close(); err != nil {
		return err
	}
	if err := db.Close(); err != nil {
		return err
	}
	verified, err := openArchiveIndex(path, true)
	if err != nil {
		return err
	}
	defer verified.Close()
	var fingerprint string
	var count int
	const verify = "SELECT (SELECT fingerprint FROM snapshot WHERE id = 1), count(*) FROM (SELECT cve, first_score, score, partial FROM lev) AS scores"
	if err := verified.QueryRowContext(ctx, verify).Scan(&fingerprint, &count); err != nil {
		return err
	}
	if fingerprint != manifest.sourceFingerprint() || count != len(findings) {
		return errors.New("published LEV archive index does not match its build")
	}
	return nil
}

func finishIndexFile(ctx context.Context, path string) (*archiveIndexFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: archiveReader{ctx, file}, N: archiveIndexDatabaseLimit + 1}
	_, err = io.Copy(hash, limited)
	if err = errors.Join(err, file.Close()); err != nil {
		return nil, err
	}
	if limited.N == 0 {
		return nil, errors.New("archive index exceeds its size limit")
	}
	if err := sealArchiveFile(path); err != nil {
		return nil, err
	}
	identity, err := archiveIndexIdentity(path)
	if err != nil {
		return nil, err
	}
	return &archiveIndexFile{SHA256: hex.EncodeToString(hash.Sum(nil)), Identity: identity}, nil
}
