package executor

import (
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"testing"
	"time"
)

func approved(t *testing.T) (*kube.Task, *kube.Plan, *kube.Approval, *unstructured.Unstructured, policy.Config, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	u := testkit.Resource("v1", "ConfigMap", "demo", "settings", "target-uid", map[string]any{"data": map[string]any{"mode": "broken"}})
	target := api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "settings", UID: "target-uid"}
	c := policy.Config{Capabilities: []policy.Capability{{APIVersion: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespace: "demo", Names: []string{"settings"}, Types: []string{"PatchResource"}, Paths: map[string]policy.ValueRule{"/data/mode": {Values: []any{"healthy"}}}, Risk: "low", RequireApproval: true}}}
	task := &kube.Task{Object: testkit.Resource(api.Group+"/"+api.Version, "AgentTask", "demo", "fix", "task-uid", nil), Spec: api.TaskSpec{Mode: "HumanApproved", TargetRef: target, Objective: "fix", Limits: api.DefaultLimits()}, Status: api.TaskStatus{ObservedGeneration: 1, Phase: "AwaitingApproval", PlanRef: &api.ObjectRef{Name: "plan", UID: "plan-uid"}}}
	baseline, _ := api.DigestTarget(u)
	p := &kube.Plan{Object: testkit.Resource(api.Group+"/"+api.Version, "ActionPlan", "demo", "plan", "plan-uid", nil), Spec: api.PlanSpec{TaskRef: api.ObjectRef{Name: "fix", UID: "task-uid"}, TaskGeneration: 1, TargetRef: target, Preconditions: api.Preconditions{SpecDigest: baseline}, PolicyDigest: policy.PolicyDigest(c), Diagnosis: "wrong mode", Risk: "low", Actions: []api.Action{{ID: "repair", Type: "PatchResource", Target: target, Patch: []api.PatchOp{{Op: "replace", Path: "/data/mode", Value: "healthy"}}}}, Verification: api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 300, StableWindowSeconds: 120}}}
	p.Spec.Digest, _ = api.DigestPlan(p.Spec)
	a := &kube.Approval{Object: testkit.Resource(api.Group+"/"+api.Version, "ActionApproval", "demo", "approve", "approval-uid", nil), Spec: api.ApprovalSpec{TaskUID: "task-uid", PlanUID: "plan-uid", PlanDigest: p.Spec.Digest, ExpiresAt: now.Add(15 * time.Minute)}}
	a.Object.SetCreationTimestamp(testkit.Timestamp(now))
	return task, p, a, u, c, now
}
func TestApprovalUIDDigestExpiryAndPolicy(t *testing.T) {
	task, p, a, u, c, now := approved(t)
	if e := ValidateApproval(task, p, a, u, c, now); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*kube.Approval){func(a *kube.Approval) { a.Spec.TaskUID = "fake" }, func(a *kube.Approval) { a.Spec.PlanUID = "fake" }, func(a *kube.Approval) { a.Spec.PlanDigest = "fake" }, func(a *kube.Approval) { a.Spec.ExpiresAt = now.Add(-time.Second) }, func(a *kube.Approval) { a.Spec.ExpiresAt = now.Add(time.Hour) }} {
		_, _, bad, _, _, _ := approved(t)
		change(bad)
		if ValidateApproval(task, p, bad, u, c, now) == nil {
			t.Fatal("invalid approval accepted")
		}
	}
	c.Capabilities = nil
	if ValidateApproval(task, p, a, u, c, now) == nil {
		t.Fatal("changed policy accepted")
	}
}
func TestStatusChangesDoNotInvalidateApproval(t *testing.T) {
	task, p, a, u, c, now := approved(t)
	u.SetResourceVersion("2")
	u.Object["status"] = map[string]any{"ready": "yes"}
	if e := ValidateApproval(task, p, a, u, c, now); e != nil {
		t.Fatal(e)
	}
}
func TestTargetReplacementAndSpecChangeInvalidateApproval(t *testing.T) {
	task, p, a, u, c, now := approved(t)
	u.SetUID("replacement")
	if ValidateApproval(task, p, a, u, c, now) == nil {
		t.Fatal("replacement accepted")
	}
	u.SetUID("target-uid")
	_ = unstructured.SetNestedField(u.Object, "other", "data", "mode")
	if ValidateApproval(task, p, a, u, c, now) == nil {
		t.Fatal("changed config accepted")
	}
	task.Object.SetGeneration(2)
	if ValidateApproval(task, p, a, u, c, now) == nil {
		t.Fatal("changed intent accepted")
	}
}
func TestApprovalReplayDenied(t *testing.T) {
	task, p, a, u, c, now := approved(t)
	p.Status.Phase = "Succeeded"
	if ValidateApproval(task, p, a, u, c, now) == nil {
		t.Fatal("completed approval replayed")
	}
	p.Status.Phase = "Executing"
	p.Status.ApprovalUID = "another-approval"
	if ValidateApproval(task, p, a, u, c, now) == nil {
		t.Fatal("approval identity replaced")
	}
}
