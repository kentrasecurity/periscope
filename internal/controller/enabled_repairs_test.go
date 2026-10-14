package controller

import (
	"strings"
	"testing"

	"github.com/kentrasecurity/periscope/internal/policy"
)

func TestEnabledRepairsNameStorageClasses(t *testing.T) {
	repairs := policy.Repairs{Storage: policy.StorageRepairs{ReplaceUnboundClaims: true}}
	lines := enabledRepairs(repairs, []string{"local-path", "longhorn"})
	if len(lines) != 1 || !strings.Contains(lines[0], "[local-path longhorn]") || !strings.Contains(lines[0], "nearest") {
		t.Fatalf("storage classes not offered for claim replacement: %v", lines)
	}
	if lines := enabledRepairs(repairs, nil); strings.Contains(lines[0], "StorageClasses are") {
		t.Fatalf("storage classes claimed without a list: %v", lines)
	}
	if lines := enabledRepairs(policy.Repairs{}, []string{"longhorn"}); len(lines) != 0 {
		t.Fatalf("repairs offered without opt-in: %v", lines)
	}
}
