// SPDX-License-Identifier: MIT

package first

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"ex-sbom/client/cisa"
)

const maxReservationBytes = 32 << 20

// ReadCVEReservations reads dates for the supplied CVEs, or all CVEs when cves is nil.
// A malformed document returns no dates. Invalid individual entries do not prevent use of the others.
func ReadCVEReservations(ctx context.Context, path string, cves []string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxReservationBytes {
		return nil, fmt.Errorf("invalid CVE reservation file type or size")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	limited := &io.LimitedReader{R: file, N: maxReservationBytes + 1}
	decoder := json.NewDecoder(limited)
	if start, err := decoder.Token(); err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("invalid CVE reservation JSON object")
	}
	wanted := make(map[string]bool, len(cves))
	for _, id := range cves {
		wanted[id] = true
	}
	dates := make(map[string]string)
	badRows := 0
	for decoder.More() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		id := key.(string) // JSON object keys are strings.
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, err
		}
		if cves != nil && !wanted[id] {
			continue
		}
		var date string
		_, duplicate := dates[id]
		valueErr := json.Unmarshal(raw, &date)
		_, dateErr := time.Parse(time.DateOnly, date)
		if valueErr != nil || dateErr != nil || duplicate || !cisa.IsCVE(id) {
			badRows++
			date = ""
		}
		dates[id] = date
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, fmt.Errorf("invalid CVE reservation JSON object")
	}
	if err := decoder.Decode(new(any)); err != io.EOF || limited.N == 0 {
		return nil, fmt.Errorf("invalid trailing data or size for CVE reservations")
	}
	if badRows > 0 {
		return dates, fmt.Errorf("ignored %d invalid or duplicate CVE reservation entries", badRows)
	}
	return dates, nil
}
