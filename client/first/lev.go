// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package first

import (
	"math"
	"strconv"
	"time"
)

// LEVMethod identifies the calculation used for persisted LEV values.
const LEVMethod = "nist-cswp41-eq10-v1"

// ParseProbability distinguishes an actual zero from absent or invalid data.
func ParseProbability(raw string) (float64, bool) {
	p, err := strconv.ParseFloat(raw, 64)
	return p, err == nil && p >= 0 && p <= 1
}

// CalculateLEV implements NIST CSWP 41, equation 10. firstDate is the
// independently established first EPSS date for the CVE. assessmentDate is the
// inclusive end of the historical period. Each window requires its first day's
// EPSS score. A truncated history must not be used to infer firstDate.
func CalculateLEV(series []TimeSeries, firstDate, assessmentDate string) (float64, bool) {
	start, errStart := time.Parse(time.DateOnly, firstDate)
	end, errEnd := time.Parse(time.DateOnly, assessmentDate)
	if errStart != nil || errEnd != nil || start.After(end) {
		return 0, false
	}

	end = end.AddDate(0, 0, 1)
	scores := make(map[string]float64, len(series))
	for _, entry := range series {
		day, err := time.Parse(time.DateOnly, entry.Date)
		if err != nil {
			return 0, false
		}
		if day.Before(start) || !day.Before(end) {
			continue
		}
		score, valid := ParseProbability(entry.EPSS)
		if old, duplicate := scores[entry.Date]; !valid || (duplicate && old != score) {
			return 0, false
		}
		scores[entry.Date] = score
	}

	const window = 30 * 24 * time.Hour
	logSurvival := 0.0
	for day := start; day.Before(end); day = day.Add(window) {
		score, found := scores[day.Format(time.DateOnly)]
		if !found {
			return 0, false
		}
		fraction := float64(min(end.Sub(day), window)) / float64(window)
		logSurvival += math.Log1p(-score * fraction)
	}
	return -math.Expm1(logSurvival), true
}
