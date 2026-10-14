package admission

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"testing"
)

func TestMultiTargetAdmissionCrossNamespace(t *testing.T) {
	v, b, r := requestSetup(t)
	p := b.Plans["demo/plan"]
	task := b.Tasks["demo/fix"]
	v.Policy = policy.Config{CoordinationNamespace: "demo", Authorization: "RBAC", Namespaces: []string{"demo", "other"}}
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo", "other"}}
	other := testkit.Resource("v1", "ConfigMap", "other", "settings", "other", map[string]any{"data": map[string]any{"mode": "broken"}})
	b.PutResource(other)
	target := api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "other", Name: "settings", UID: "other"}
	digest, _ := api.DigestTarget(other)
	p.Spec.Targets = []api.TargetBinding{{ID: "goal", Target: p.Spec.TargetRef, Preconditions: p.Spec.Preconditions}, {ID: "other", Target: target, Preconditions: api.Preconditions{SpecDigest: digest}}}
	action := p.Spec.Actions[0]
	action.Target = target
	action.BindingID = "other"
	p.Spec.Actions = []api.Action{action}
	p.Spec.PolicyDigest = policy.PolicyDigest(v.Policy)
	p.Spec.Digest, _ = api.DigestPlan(p.Spec)
	b.ApprovalItems["demo/approve"].Spec.PlanDigest = p.Spec.Digest
	desired, _ := executor.PrepareResult(p, action, other)
	after, _ := executor.ResultDigest(desired, action)
	p.Status.Entries[0].BeforeDigest = digest
	p.Status.Entries[0].AfterDigest = after
	b.Claims[api.ClaimKey(target)] = string(p.Object.GetUID())
	r.Request.Namespace = "other"
	r.Request.OldObject.Raw, _ = json.Marshal(other.Object)
	r.Request.Object.Raw, _ = json.Marshal(desired.Object)
	if result := v.Validate(context.Background(), r); !result.Allowed {
		t.Fatalf("scoped cross namespace denied: %v", result.Result)
	}
	delete(b.Claims, api.ClaimKey(p.Spec.TargetRef))
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("missing primary claim admitted")
	}
}
