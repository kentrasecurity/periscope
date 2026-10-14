package executor

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/policy"
	"testing"
	"time"
)

func TestCreateResourceResumesWithAssignedUID(t *testing.T) {
	e, b, p, now := execution(t)
	delete(b.Resources, "demo/settings")
	p.Spec.TargetRef.UID = ""
	p.Spec.Preconditions.SpecDigest = "absent"
	blueprint := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "settings", "namespace": "demo"}, "data": map[string]any{"mode": "healthy"}}
	e.Policy.Capabilities = []policy.Capability{{APIVersion: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespace: "demo", Names: []string{"settings"}, Types: []string{"CreateResource"}, CreateObject: blueprint, Risk: "low", RequireApproval: true}}
	p.Spec.PolicyDigest = policy.PolicyDigest(e.Policy)
	p.Spec.Actions = []api.Action{{ID: "create", Type: "CreateResource", Target: p.Spec.TargetRef, Object: blueprint}}
	p.Spec.Verification = api.Verification{Type: "ResourceExists", TimeoutSeconds: 300, StableWindowSeconds: 1}
	p.Spec.Digest, _ = api.DigestPlan(p.Spec)
	b.Tasks["demo/fix"].Spec.TargetRef = p.Spec.TargetRef
	b.ApprovalItems["demo/approve"].Spec.PlanDigest = p.Spec.Digest
	b.WriteThenError = true
	_ = e.Reconcile(context.Background(), "demo", "fix")
	b.WriteThenError = false
	for range 3 {
		*now = now.Add(2 * time.Second)
		_ = e.Reconcile(context.Background(), "demo", "fix")
	}
	if b.Mutations != 1 || p.Status.Phase != "Succeeded" {
		t.Fatalf("created UID recovery failed: %d %s", b.Mutations, p.Status.Phase)
	}
}
