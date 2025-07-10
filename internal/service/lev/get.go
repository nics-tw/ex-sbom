// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package lev

import (
	"context"
	"ex-sbom/client/first"
	"ex-sbom/util"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
)

type (
	ChunkResult struct {
		Data []first.EPSS
		Err  error
	}
)

const (
	chunkSize   = 100
	workerCount = 10
)

func GetByChunk(cves []string) (map[string]first.EPSS, error) {
	if len(cves) == 0 {
		return nil, fmt.Errorf("no CVEs provided")
	}

	c := first.New()
	ctx := context.Background()

	chunks := util.ChunkSlice(cves, chunkSize)
	resultsCh := make(chan ChunkResult, len(chunks))
	jobsCh := make(chan []string, len(chunks))

	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for chunk := range jobsCh {
				select {
				case <-ctx.Done():
					resultsCh <- ChunkResult{Err: ctx.Err()}
					return
				default:
					epssResponse, err := c.GetEPSS(chunk)
					if err != nil {
						resultsCh <- ChunkResult{Err: fmt.Errorf("failed to fetch chunk: %w", err)}
					} else {
						resultsCh <- ChunkResult{Data: epssResponse.Data}
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobsCh)
		for _, chunk := range chunks {
			select {
			case <-ctx.Done():
				return
			case jobsCh <- chunk:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var allResults []first.EPSS
	var errors []error
	expectedResults := len(chunks)

	for result := range resultsCh {
		if result.Err != nil {
			errors = append(errors, result.Err)
		} else {
			allResults = append(allResults, result.Data...)
		}

		expectedResults--

		if expectedResults == 0 {
			break
		}
	}

	if len(errors) > 0 {
		if len(allResults) == 0 {
			return nil, fmt.Errorf("all requests failed: %v", errors)
		}

		slog.Error("Warning: some chunks failed", "failed_chunks", len(errors), "total_chunks", len(chunks))
	}

	if len(allResults) == 0 {
		return nil, fmt.Errorf("no EPSS data found for the provided CVEs")
	}

	var resultMap = make(map[string]first.EPSS)

	for _, epss := range allResults {
		epssNum, _ := strconv.ParseFloat(epss.EPSS, 64)
		epss.EPSSNum = epssNum

		resultMap[epss.CVE] = epss
	}

	return resultMap, nil
}
