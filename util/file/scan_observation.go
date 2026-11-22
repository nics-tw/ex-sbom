// SPDX-License-Identifier: MIT

package file

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"
)

type PackageVersion struct {
	Ecosystem string
	Name      string
	Version   string
}

// QueryObservation describes the OSV responses seen during one scan.
type QueryObservation struct {
	CompletedAt     time.Time
	Packages        map[PackageVersion]struct{}
	MinimumFindings int
}

type osvRequest struct {
	path    string
	payload [sha256.Size]byte
}

type osvResponse struct {
	err             error
	batch           bool
	packages        []PackageVersion
	minimumFindings int
}

type scanTransport struct {
	base http.RoundTripper
	mu   sync.Mutex
	seen map[osvRequest]osvResponse
}

func (t *scanTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	batch := r.Method == http.MethodPost && r.URL.Path == osvdev.QueryBatchEndpoint
	detail := r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, osvdev.GetEndpoint+"/")
	if r.URL.Scheme+"://"+r.URL.Host != osvdev.DefaultBaseURL || (!batch && !detail) {
		return t.base.RoundTrip(r)
	}

	key := osvRequest{path: r.URL.Path}
	entry := osvResponse{batch: batch}
	var queries api.BatchQuery
	if batch {
		// OSVClient builds each request with a bytes.Buffer, so GetBody can
		// supply its query identities without consuming the actual request.
		body, err := readQueryBody(r)
		if err != nil {
			t.record(key, osvResponse{err: err})
			_ = r.Body.Close()
			return nil, err
		}
		key.payload = sha256.Sum256(body)
		if err := protojson.Unmarshal(body, &queries); err != nil {
			err := errors.New("invalid OSV batch request")
			t.record(key, osvResponse{err: err})
			_ = r.Body.Close()
			return nil, err
		}
	}

	response, err := t.base.RoundTrip(r)
	switch {
	case err != nil:
		entry.err = errors.New("OSV request could not be completed")
	case response.StatusCode < 200 || response.StatusCode >= 300:
		entry.err = fmt.Errorf("OSV query returned HTTP %d", response.StatusCode)
		// Preserve the status for the client's retry policy without exposing
		// a response body from an upstream error in scanner output.
		_ = response.Body.Close()
		response.Body = http.NoBody
	default:
		var body []byte
		body, entry.err = readOSVBody(response.Body)
		if entry.err == nil {
			response.Body = io.NopCloser(bytes.NewReader(body))
			switch {
			case batch:
				entry.packages, entry.minimumFindings, entry.err = completedQueries(&queries, body)
			case detail:
				var vuln osvschema.Vulnerability
				if protojson.Unmarshal(body, &vuln) != nil || vuln.GetId() != strings.TrimPrefix(r.URL.Path, osvdev.GetEndpoint+"/") {
					entry.err = errors.New("invalid OSV vulnerability details")
				}
			}
		}
		if entry.err != nil {
			_ = response.Body.Close()
			response, err = nil, entry.err
		}
	}

	t.record(key, entry)
	return response, err
}

func (t *scanTransport) record(key osvRequest, entry osvResponse) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// OSV can retry the same payload. A later successful response for that
	// request clears a transient failure, without clearing other failures.
	t.seen[key] = entry
}

func readQueryBody(r *http.Request) ([]byte, error) {
	if r.GetBody == nil {
		return nil, errors.New("OSV batch request cannot be inspected")
	}
	body, err := r.GetBody()
	if err != nil {
		return nil, errors.New("OSV batch request cannot be read")
	}
	return readOSVBody(body)
}

func readOSVBody(body io.ReadCloser) ([]byte, error) {
	defer body.Close()
	const limit = 32 << 20
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, errors.New("unable to read OSV query data")
	}
	if len(data) > limit {
		return nil, errors.New("OSV query data exceeded the size limit")
	}
	return data, nil
}

func completedQueries(queries *api.BatchQuery, data []byte) ([]PackageVersion, int, error) {
	var result api.BatchVulnerabilityList
	if protojson.Unmarshal(data, &result) != nil || len(result.GetResults()) != len(queries.GetQueries()) {
		return nil, 0, errors.New("incomplete or invalid OSV batch response")
	}

	complete := make([]PackageVersion, 0, len(result.GetResults()))
	minimumFindings := 0
	for i, item := range result.GetResults() {
		minimumFindings += len(item.GetVulns())
		if item == nil || item.GetNextPageToken() != "" {
			continue
		}
		query := queries.GetQueries()[i]
		pkg := query.GetPackage()
		if name, version := pkg.GetName(), query.GetVersion(); name != "" && version != "" && pkg.GetEcosystem() != "" {
			complete = append(complete, PackageVersion{Ecosystem: pkg.GetEcosystem(), Name: name, Version: version})
		}
	}
	return complete, minimumFindings, nil
}

func (t *scanTransport) observation() (QueryObservation, error) {
	observed := QueryObservation{Packages: make(map[PackageVersion]struct{})}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, entry := range t.seen {
		if entry.err != nil {
			return QueryObservation{}, entry.err
		}
		// A batch page counts returned component/finding pairs. Keep a
		// conservative lower bound when paging or requests overlap.
		observed.MinimumFindings = max(observed.MinimumFindings, entry.minimumFindings)
		if entry.batch {
			observed.CompletedAt = time.Now().UTC()
		}
		for _, pkg := range entry.packages {
			observed.Packages[pkg] = struct{}{}
		}
	}
	return observed, nil
}
