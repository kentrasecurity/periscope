package executor

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"testing"
	"time"
)

func TestScopedMultiTargetRecoveryAndStaleBinding(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovery", true: "stale"}[stale], func(t *testing.T) {
			e, b, p, now := execution(t)
			e.Policy = policy.Config{CoordinationNamespace: "demo", Authorization: "RBAC", Namespaces: []string{"demo", "other"}}
			task := b.Tasks["demo/fix"]
			task.Spec.TargetRef = api.TargetRef{}
			task.Spec.Scope = &api.Scope{Namespaces: []string{"demo", "other"}}
			second := testkit.Resource("v1", "ConfigMap", "other", "settings", "second", map[string]any{"data": map[string]any{"mode": "bad"}})
			b.PutResource(second)
			other := api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "other", Name: "settings", UID: "second"}
			digest, _ := api.DigestTarget(second)
			p.Spec.Targets = []api.TargetBinding{{ID: "primary", Target: p.Spec.TargetRef, Preconditions: p.Spec.Preconditions}, {ID: "other", Target: other, Preconditions: api.Preconditions{SpecDigest: digest}}}
			p.Spec.Actions[0].BindingID = "primary"
			p.Spec.Actions = append(p.Spec.Actions, api.Action{ID: "second", BindingID: "other", Type: "PatchResource", Target: other, Patch: []api.PatchOp{{Op: "replace", Path: "/data/mode", Value: "healthy"}}})
			p.Spec.PolicyDigest = policy.PolicyDigest(e.Policy)
			p.Spec.Digest, _ = api.DigestPlan(p.Spec)
			b.ApprovalItems["demo/approve"].Spec.PlanDigest = p.Spec.Digest
			if stale {
				second.Object["data"].(map[string]any)["mode"] = "changed"
				b.PutResource(second)
			}
			for range 3 {
				if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
					t.Fatal(err)
				}
				*now = now.Add(2 * time.Second)
			}
			if stale {
				if b.Mutations != 0 {
					t.Fatal("stale related target allowed writes")
				}
				return
			}
			if b.Mutations != 2 || p.Status.Phase != "Succeeded" {
				t.Fatalf("mutations=%d phase=%s", b.Mutations, p.Status.Phase)
			}
		})
	}
}

func TestPartialMultiTargetRecoveryDoesNotReplayAppliedWrites(t *testing.T) {
	e, b, p, now := execution(t)
	e.Policy = policy.Config{CoordinationNamespace: "demo", Authorization: "RBAC", Namespaces: []string{"demo"}}
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}}
	other := testkit.Resource("v1", "ConfigMap", "demo", "other", "other-uid", map[string]any{"data": map[string]any{"mode": "bad"}})
	b.PutResource(other)
	ref := api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "other", UID: "other-uid"}
	digest, _ := api.DigestTarget(other)
	p.Spec.Targets = []api.TargetBinding{{ID: "goal", Target: p.Spec.TargetRef, Preconditions: p.Spec.Preconditions}, {ID: "other", Target: ref, Preconditions: api.Preconditions{SpecDigest: digest}}}
	p.Spec.Actions[0].BindingID = "goal"
	p.Spec.Actions = append(p.Spec.Actions, api.Action{ID: "second", BindingID: "other", Target: ref, Type: "PatchResource", Patch: []api.PatchOp{{Op: "replace", Path: "/data/mode", Value: "healthy"}}})
	p.Spec.PolicyDigest = policy.PolicyDigest(e.Policy)
	p.Spec.Digest, _ = api.DigestPlan(p.Spec)
	b.ApprovalItems["demo/approve"].Spec.PlanDigest = p.Spec.Digest
	b.WriteThenError = true
	if err := e.Reconcile(context.Background(), "demo", "fix"); err == nil {
		t.Fatal("expected interrupted committed write")
	}
	b.WriteThenError = false
	if b.Mutations != 1 {
		t.Fatal("first write missing")
	}
	other.Object["data"].(map[string]any)["mode"] = "owner-edit"
	b.PutResource(other)
	*now = now.Add(time.Second)
	_ = e.Reconcile(context.Background(), "demo", "fix")
	if b.Mutations != 1 {
		t.Fatal("replayed write or overwrote concurrent edit")
	}
}
func TestExplicitDeleteCreateReplacement(t *testing.T) {
	e, b, p, now := execution(t)
	e.Policy = policy.Config{CoordinationNamespace: "demo", Authorization: "RBAC", Namespaces: []string{"demo"}}
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}}
	ref := p.Spec.TargetRef
	createRef := ref
	createRef.UID = ""
	p.Spec.Targets = []api.TargetBinding{{ID: "old", Target: ref, Preconditions: p.Spec.Preconditions}, {ID: "new", Target: createRef, Preconditions: api.Preconditions{SpecDigest: "absent"}, AfterActionID: "delete"}}
	p.Spec.Actions = []api.Action{{ID: "delete", BindingID: "old", Type: "DeleteResource", Target: ref}, {ID: "create", BindingID: "new", Type: "CreateResource", Target: createRef, Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": ref.Name, "namespace": ref.Namespace}, "data": map[string]any{"mode": "healthy"}}}}
	p.Spec.PolicyDigest = policy.PolicyDigest(e.Policy)
	p.Spec.Digest, _ = api.DigestPlan(p.Spec)
	b.ApprovalItems["demo/approve"].Spec.PlanDigest = p.Spec.Digest
	for range 3 {
		if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(2 * time.Second)
	}
	if b.Mutations != 2 || p.Status.Phase != "Succeeded" {
		t.Fatalf("replacement %d %s", b.Mutations, p.Status.Phase)
	}
}
