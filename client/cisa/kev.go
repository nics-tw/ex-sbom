// SPDX-License-Identifier: MIT

package cisa

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const CatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

func IsCVE(id string) bool { return cveID.MatchString(id) }

type Catalog struct {
	Version     string
	RetrievedAt time.Time
	entries     map[string]struct{}
}

func (c Catalog) Contains(id string) bool {
	_, found := c.entries[id]
	return found
}

var cache struct {
	sync.Mutex
	catalog Catalog
	err     error
	retryAt time.Time
}

// Current reuses a successfully checked catalog for one hour. Errors are
// cached briefly to keep catalog downtime from delaying repeated imports.
func Current() (Catalog, error) {
	cache.Lock()
	defer cache.Unlock()
	if time.Now().Before(cache.retryAt) {
		return cache.catalog, cache.err
	}
	cache.catalog, cache.err = fetch(&http.Client{Timeout: 5 * time.Second}, CatalogURL)
	delay := time.Hour
	if cache.err != nil {
		delay = time.Minute
	}
	cache.retryAt = time.Now().Add(delay)
	return cache.catalog, cache.err
}

func fetch(client *http.Client, url string) (Catalog, error) {
	resp, err := client.Get(url)
	if err != nil {
		return Catalog{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Catalog{}, fmt.Errorf("KEV catalog HTTP status %d", resp.StatusCode)
	}
	var data struct {
		Version         string `json:"catalogVersion"`
		Count           int    `json:"count"`
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 16<<20))
	if err := decoder.Decode(&data); err != nil {
		return Catalog{}, fmt.Errorf("decode KEV catalog: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Catalog{}, fmt.Errorf("unexpected content after KEV catalog")
	}
	if strings.TrimSpace(data.Version) == "" || data.Count < 1 || data.Count != len(data.Vulnerabilities) {
		return Catalog{}, fmt.Errorf("invalid KEV catalog metadata or entry count")
	}
	entries := make(map[string]struct{}, data.Count)
	for _, item := range data.Vulnerabilities {
		if !IsCVE(item.CVE) {
			return Catalog{}, fmt.Errorf("invalid CVE identifier in KEV catalog")
		}
		entries[item.CVE] = struct{}{}
	}
	if len(entries) != data.Count {
		return Catalog{}, fmt.Errorf("duplicate CVE identifiers in KEV catalog")
	}
	return Catalog{Version: data.Version, RetrievedAt: time.Now().UTC(), entries: entries}, nil
}
