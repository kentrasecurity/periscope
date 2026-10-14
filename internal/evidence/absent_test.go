package evidence

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"testing"
)

func TestMissingTargetIsExplicitEvidence(t *testing.T) {
	c := Collector{Reader: testkit.NewMemory(), Policy: config(), MaxToolCalls: 30}
	b, e := c.Collect(context.Background(), api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Name: "settings"}, "demo")
	if e != nil || !b.Absent || b.Target == nil || len(b.Evidence) == 0 {
		t.Fatalf("missing resource cannot be investigated: %v", e)
	}
}
