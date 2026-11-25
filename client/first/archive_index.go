// SPDX-License-Identifier: MIT

package first

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ex-sbom/client/cisa"

	_ "github.com/marcboeker/go-duckdb"
)

const (
	archiveIndexVersion       = 1
	archiveIndexDBName        = "lev-index.duckdb"
	archiveIndexManifestName  = "lev-index.json"
	archiveIndexManifestLimit = 2 << 20
	// ArchiveIndexReservations is the optional reservation file in a sealed snapshot.
	ArchiveIndexReservations = "cve-reservations.json"
)

type archiveIndexFile struct {
	SHA256   string `json:"sha256"`
	Identity string `json:"identity"`
}

type archiveIndexManifest struct {
	Version      int                 `json:"version"`
	Method       string              `json:"method"`
	FirstDay     string              `json:"first_day"`
	AsOf         string              `json:"as_of"`
	Days         []*archiveIndexFile `json:"days"`
	Reservations *archiveIndexFile   `json:"reservations,omitempty"`
	Index        *archiveIndexFile   `json:"index"`
}

func archiveDayName(day string) string { return "epss_scores-" + day + ".csv.gz" }

func archiveIndexDates(asOf string) ([]string, error) {
	end, err := time.Parse(time.DateOnly, asOf)
	start, _ := time.Parse(time.DateOnly, FirstArchiveDay)
	if err != nil || end.Before(start) || !end.Before(time.Now().UTC().Truncate(24*time.Hour)) {
		return nil, fmt.Errorf("invalid EPSS archive cutoff %q", asOf)
	}
	var dates []string
	for day := start; !day.After(end); day = day.AddDate(0, 0, 1) {
		dates = append(dates, day.Format(time.DateOnly))
	}
	return dates, nil
}

func (m *archiveIndexManifest) sourceFingerprint() string {
	hash := sha256.New()
	fmt.Fprintln(hash, m.Version, m.Method, m.FirstDay, m.AsOf)
	for _, entry := range m.Days {
		if entry == nil {
			fmt.Fprintln(hash, "-")
		} else {
			fmt.Fprintln(hash, entry.SHA256)
		}
	}
	if m.Reservations != nil {
		fmt.Fprintln(hash, m.Reservations.SHA256)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func openArchiveIndex(path string, readOnly bool) (*sql.DB, error) {
	if strings.ContainsAny(path, "?#%") {
		return nil, errors.New("archive index path must not contain ?, # or %")
	}
	dsn := path + "?enable_external_access=false"
	if readOnly {
		dsn += "&access_mode=read_only"
	}
	return sql.Open("duckdb", dsn)
}

// LookupArchiveIndex returns results only after the entire lookup succeeds.
// Missing CVEs in a complete sealed index are unavailable.
func LookupArchiveIndex(ctx context.Context, dir, reservations, asOf string, cves []string) (map[string]HistoricalLEV, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(dir, archiveIndexManifestName)
	if _, err := os.Lstat(manifestPath); err != nil {
		return nil, err
	}
	if err := checkSealedArchiveDirectory(dir); err != nil {
		return nil, err
	}
	dirIdentity, err := archiveIndexIdentity(dir)
	if err != nil {
		return nil, err
	}
	file, manifestIdentity, err := openSealedArchiveFile(manifestPath, archiveIndexManifestLimit)
	if err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: archiveReader{ctx, file}, N: archiveIndexManifestLimit + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var manifest archiveIndexManifest
	err = decoder.Decode(&manifest)
	if err == nil && (decoder.Decode(new(any)) != io.EOF || limited.N == 0) {
		err = errors.New("invalid trailing archive manifest data")
	}
	if err = errors.Join(err, file.Close()); err != nil {
		return nil, err
	}
	dates, err := archiveIndexDates(asOf)
	if err != nil {
		return nil, err
	}
	if manifest.Version != archiveIndexVersion || manifest.Method != LEVMethod ||
		manifest.FirstDay != FirstArchiveDay || manifest.AsOf != asOf || len(manifest.Days) != len(dates) ||
		manifest.Index == nil {
		return nil, errors.New("archive index format, period or LEV method does not match")
	}
	if err := verifyArchiveInputs(ctx, dir, reservations, dates, &manifest); err != nil {
		return nil, err
	}
	indexPath := filepath.Join(dir, archiveIndexDBName)
	matched, err := verifySealedArchiveDigest(ctx, indexPath, manifest.Index, archiveIndexDatabaseLimit)
	if err != nil {
		return nil, fmt.Errorf("read sealed archive index: %w", err)
	}
	if !matched {
		return nil, errors.New("archive index failed its digest check")
	}
	result, err := queryArchiveIndex(ctx, indexPath, asOf, manifest.sourceFingerprint(), cves)
	if err != nil {
		return nil, err
	}
	if err := verifyArchiveInputs(ctx, dir, reservations, dates, &manifest); err != nil {
		return nil, err
	}
	for path, expected := range map[string]string{
		dir: dirIdentity, manifestPath: manifestIdentity, indexPath: manifest.Index.Identity,
	} {
		if got, err := archiveIndexSealedIdentity(path); err != nil || got != expected {
			return nil, fmt.Errorf("sealed archive snapshot changed during lookup: %s", filepath.Base(path))
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func openSealedArchiveFile(path string, maxBytes int64) (*os.File, string, error) {
	identity, err := sealedArchiveFileIdentity(path, maxBytes)
	if err != nil {
		return nil, "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	opened, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, "", err
	}
	named, err := os.Lstat(path)
	if err != nil || !sameArchive(opened, named) {
		file.Close()
		return nil, "", errors.New("sealed archive file changed while opening")
	}
	return file, identity, nil
}

func sealedArchiveFileIdentity(path string, maxBytes int64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() > maxBytes {
		return "", fmt.Errorf("archive file %s must be a bounded read-only regular file", filepath.Base(path))
	}
	return archiveIndexSealedIdentity(path)
}

func verifySealedArchiveDigest(ctx context.Context, path string, entry *archiveIndexFile, maxBytes int64) (bool, error) {
	file, identity, err := openSealedArchiveFile(path, maxBytes)
	if err != nil {
		return false, err
	}
	defer file.Close()
	if identity != entry.Identity {
		return false, nil
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: archiveReader{ctx, file}, N: maxBytes + 1}
	if _, err := io.Copy(hash, limited); err != nil {
		return false, err
	}
	return limited.N > 0 && hex.EncodeToString(hash.Sum(nil)) == entry.SHA256, nil
}

func verifyArchiveInputs(ctx context.Context, dir, reservationPath string, dates []string, manifest *archiveIndexManifest) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	expectedFiles := 2
	for i, day := range dates {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := filepath.Join(dir, archiveDayName(day))
		identity, err := sealedArchiveFileIdentity(path, maxArchiveBytes)
		entry := manifest.Days[i]
		if entry == nil && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if entry == nil || err != nil || identity != entry.Identity {
			return fmt.Errorf("sealed EPSS archive changed on %s", day)
		}
		expectedFiles++
	}
	if (manifest.Reservations == nil) != (reservationPath == "") {
		return errors.New("configured CVE reservations do not match the snapshot")
	}
	if manifest.Reservations != nil {
		expectedFiles++
		sealed := filepath.Join(dir, ArchiveIndexReservations)
		configured, err := filepath.Abs(reservationPath)
		if err != nil {
			return errors.New("configure the CVE reservations file inside the sealed snapshot")
		}
		if configured != sealed {
			identity, err := sealedArchiveFileIdentity(configured, maxReservationBytes)
			if err != nil || identity != manifest.Reservations.Identity {
				return errors.New("configured CVE reservations do not match the sealed file")
			}
		}
		matched, err := verifySealedArchiveDigest(ctx, sealed, manifest.Reservations, maxReservationBytes)
		if err != nil || !matched {
			return errors.New("sealed CVE reservations failed their digest check")
		}
	}
	if len(entries) != expectedFiles {
		return errors.New("unexpected files in sealed archive snapshot")
	}
	return nil
}

func queryArchiveIndex(ctx context.Context, path, asOf, fingerprint string, cves []string) (map[string]HistoricalLEV, error) {
	db, err := openArchiveIndex(path, true)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var indexed string
	if err := db.QueryRowContext(ctx, "SELECT fingerprint FROM snapshot WHERE id = 1").Scan(&indexed); err != nil {
		return nil, err
	}
	if fingerprint != indexed {
		return nil, errors.New("archive index source fingerprint does not match")
	}
	result := make(map[string]HistoricalLEV)
	for start := 0; start < len(cves); start += 512 {
		ids := cves[start:min(start+512, len(cves))]
		want := make(map[string]bool, len(ids))
		args := make([]any, len(ids))
		for i, cve := range ids {
			args[i], want[cve] = cve, true
		}
		rows, err := db.QueryContext(ctx, "SELECT cve, first_score, score, partial FROM lev WHERE cve IN (?"+strings.Repeat(",?", len(ids)-1)+")", args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			item := HistoricalLEV{AsOf: asOf}
			if err := rows.Scan(&id, &item.First, &item.Score, &item.Partial); err != nil {
				rows.Close()
				return nil, err
			}
			_, dateErr := time.Parse(time.DateOnly, item.First)
			if !want[id] || !cisa.IsCVE(id) || dateErr != nil || item.First < FirstArchiveDay ||
				item.First > asOf || !(item.Score >= 0 && item.Score <= 1) {
				rows.Close()
				return nil, errors.New("invalid result in the LEV archive index")
			}
			result[id] = item
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, err
		}
	}
	return result, nil
}
