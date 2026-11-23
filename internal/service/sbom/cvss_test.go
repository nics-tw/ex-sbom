//go:build unit

package ssbom

import (
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/require"
)

func TestAdvisoryCVSS(t *testing.T) {
	v := &osvschema.Vulnerability{Severity: []*osvschema.Severity{
		{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{Type: osvschema.Severity_CVSS_V4, Score: "invalid"},
	}}
	score, standard := advisoryCVSS(v)
	require.Equal(t, "9.8", score)
	require.Equal(t, "3.1", standard)
}
