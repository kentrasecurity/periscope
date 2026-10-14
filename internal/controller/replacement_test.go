package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/observation"
	"github.com/kentrasecurity/periscope/internal/testkit"
)

// Removing replacement bindings would fail this test before any mutation.
func TestSingleTargetPodReplacementPreservesOriginalGoal(t *testing.T) {
	for _, mode := range []string{"HumanApproved", "Automatic"} {
		t.Run(mode, func(t *testing.T) {
			i, b, _ := setup(t)
			i.Policy.Authorization = "RBAC"
			i.Collector.Policy = i.Policy
			pod := testkit.Resource("v1", "Pod", "demo", "app", "old-pod", map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "known", "command": []any{"/restart"}}}}, "status": map[string]any{"phase": "Pending"}})
			b.PutResource(pod)
			task := b.Tasks["demo/fix"]
			task.Spec.TargetRef = api.TargetRef{APIVersion: "v1", Kind: "Pod", Name: "app"}
			task.Spec.Mode = mode
			task.Spec.Verification = &api.Verification{Type: "PodRecovery", TimeoutSeconds: 180, StableWindowSeconds: 1}
			desired := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "app", "namespace": "demo"}, "spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "known", "readinessProbe": map[string]any{"httpGet": map[string]any{"path": "/healthz", "port": float64(8080)}}}}}}
			i.Model = fixedModel{decision: llm.Decision{Diagnosis: "recreate immutable command and probe", Actions: []api.Action{{ID: "delete", Type: "DeleteResource"}, {ID: "create", Type: "CreateResource", Object: desired}}, Verification: *task.Spec.Verification}}
			if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
				t.Fatal(err)
			}
			if task.Status.PlanRef == nil {
				t.Fatalf("replacement not planned: %s %s", task.Status.Phase, task.Status.Report)
			}
			p := b.Plans["demo/"+task.Status.PlanRef.Name]
			if len(p.Spec.Targets) != 2 || p.Spec.Targets[1].AfterActionID != "delete" || p.Spec.Actions[1].Target.UID != "" {
				t.Fatalf("missing deletion dependency: %+v", p.Spec.Targets)
			}
			digest := task.Status.Incident.OriginalChecksDigest
			incidentID := task.Status.Incident.ID
			approval := b.ApprovalItems["demo/"+task.Status.ApprovalRef.Name]
			now := time.Now().UTC()
			ex := executor.Executor{Backend: b, Policy: i.Policy, Now: func() time.Time { return now }}
			if mode == "HumanApproved" {
				if err := ex.Reconcile(context.Background(), "demo", "fix"); err != nil {
					t.Fatal(err)
				}
				if b.Mutations != 0 {
					t.Fatal("replacement before human approval")
				}
				approval.Spec.Decision = "Approve"
			}
			if err := ex.Reconcile(context.Background(), "demo", "fix"); err != nil {
				t.Fatal(err)
			}
			if b.Mutations != 2 || p.Status.Phase != "Verifying" {
				t.Fatalf("replacement mutations=%d phase=%s conditions=%+v", b.Mutations, p.Status.Phase, p.Status.Conditions)
			}
			replacement := b.Resources["demo/app"]
			if string(replacement.GetUID()) == "old-pod" {
				t.Fatal("Pod was not recreated")
			}
			if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
				t.Fatal(err)
			}
			if task.Status.Incident == nil || task.Status.Incident.ID != incidentID || task.Status.Incident.OriginalChecksDigest != digest {
				t.Fatal("replacement lost original goal")
			}
			replacement.Object["status"] = map[string]any{"phase": "Running", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}, "containerStatuses": []any{map[string]any{"name": "app", "image": "known", "ready": true, "containerID": "runtime://new", "restartCount": int64(0), "state": map[string]any{"running": map[string]any{}}}}}
			b.PutResource(replacement)
			for range 2 {
				now = now.Add(2 * time.Second)
				if err := ex.Reconcile(context.Background(), "demo", "fix"); err != nil {
					t.Fatal(err)
				}
			}
			if p.Status.Phase != "Succeeded" || b.Mutations != 2 {
				t.Fatalf("original recovery not verified: %s %+v", p.Status.Phase, p.Status.Conditions)
			}
		})
	}
}

type retryToolModel struct {
	calls        int
	proposal     llm.Decision
	corrected    llm.Decision
	feedbackSeen bool
}

func (m *retryToolModel) Propose(context.Context, llm.Request) (llm.Decision, error) {
	return m.proposal, nil
}
func (m *retryToolModel) Turn(_ context.Context, c llm.Conversation) (llm.TurnResult, error) {
	m.calls++
	if m.calls == 1 {
		return llm.TurnResult{Decision: &m.proposal}, nil
	}
	raw, _ := json.Marshal(c.Messages)
	m.feedbackSeen = strings.Contains(string(raw), "DryRunRejected")
	return llm.TurnResult{Decision: &m.corrected}, nil
}

// Removing duplicate rejection feedback would publish the second invalid patch.
func TestRepeatedRejectedPatchIsReplannedWithinModelBudget(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task := b.Tasks["demo/fix"]
	task.Spec.Mode = "Automatic"
	task.Spec.Verification = &api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 180, StableWindowSeconds: 1}
	ref := task.Spec.TargetRef
	ref.Namespace = "demo"
	ref.UID = "target-uid"
	baseline, _ := api.DigestTarget(b.Resources["demo/settings"])
	prior := &kube.Plan{Object: testkit.Resource(api.Group+"/"+api.Version, "ActionPlan", "demo", "rejected", "prior-uid", nil), Spec: api.PlanSpec{TargetRef: ref, TaskRef: api.ObjectRef{Name: "fix", UID: "task-uid"}, Preconditions: api.Preconditions{SpecDigest: baseline}, Actions: []api.Action{{ID: "old-id", Type: "PatchResource", Target: ref, Patch: []api.PatchOp{{Op: "replace", Path: "/data/mode", Value: "healthy"}}}}}, Status: api.PlanStatus{Phase: "Failed", Conditions: []api.Condition{{Reason: "DryRunRejected", Message: "field is immutable"}}}}
	b.Plans["demo/rejected"] = prior
	checks := []api.Check{api.VerificationCheck(ref, *task.Spec.Verification)}
	digest, _ := api.Hash(checks)
	task.Status.ObservedGeneration = 1
	task.Status.Incident = &api.IncidentStatus{ID: "incident", Target: ref, OriginalChecks: checks, OriginalChecksDigest: digest, Attempt: 2, PriorPlanRefs: []api.ObjectRef{{Name: "rejected", UID: "prior-uid"}}}
	task.Spec.Limits.MaxModelCalls = 3
	m := &retryToolModel{proposal: llm.Decision{Diagnosis: "same rejected patch", Actions: []api.Action{{ID: "new-id", Type: "PatchResource", Patch: prior.Spec.Actions[0].Patch}}, Verification: *task.Spec.Verification}, corrected: llm.Decision{Diagnosis: "explicit replacement", Actions: []api.Action{{ID: "delete", Type: "DeleteResource"}, {ID: "create", Type: "CreateResource", Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "settings", "namespace": "demo"}, "data": map[string]any{"mode": "healthy"}}}}, Verification: *task.Spec.Verification}}
	i.Model = m
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if m.calls != 2 || !m.feedbackSeen {
		t.Fatalf("rejected patch was not corrected: calls=%d feedback=%v", m.calls, m.feedbackSeen)
	}
	if task.Status.PlanRef == nil || b.Plans["demo/"+task.Status.PlanRef.Name].Spec.Actions[0].Type != "DeleteResource" || b.Mutations != 0 {
		t.Fatalf("invalid retry plan: %s %s", task.Status.Phase, task.Status.Report)
	}
}

func TestSingleTargetReplacementCannotWriteRelatedResource(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task := b.Tasks["demo/fix"]
	i.Model = fixedModel{decision: llm.Decision{Diagnosis: "invalid expansion", Actions: []api.Action{{ID: "delete", Type: "DeleteResource"}, {ID: "create", Type: "CreateResource", Target: api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "other"}, Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "other", "namespace": "demo"}}}}, Verification: api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 180, StableWindowSeconds: 1}}}
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if task.Status.Phase != "Blocked" || task.Status.PlanRef != nil || b.Mutations != 0 {
		t.Fatal("replacement expanded exact target scope")
	}
}

func TestRejectedProposalCorrectionStopsAtModelBudget(t *testing.T) {
	i, b, _ := setup(t)
	task := b.Tasks["demo/fix"]
	task.Spec.Limits.MaxModelCalls = 2
	ref := task.Spec.TargetRef
	ref.Namespace = "demo"
	ref.UID = "target-uid"
	before, _ := api.DigestTarget(b.Resources["demo/settings"])
	a := api.Action{ID: "old", Type: "PatchResource", Target: ref, Patch: []api.PatchOp{{Op: "replace", Path: "/data/mode", Value: "healthy"}}}
	rejected := []llm.RejectedAction{{PlanName: "rejected", Action: a, BeforeDigest: before, Reason: "DryRunRejected", Message: "immutable"}}
	proposal := llm.Decision{Diagnosis: "repeats rejected action", Actions: []api.Action{a}}
	m := &retryToolModel{proposal: proposal, corrected: proposal}
	r := observation.NewRegistry(b, i.Policy, 5)
	d, err := investigate(context.Background(), task, r, m, nil, rejected, func(d llm.Decision) error { return rejectRepeatedActions(context.Background(), b, ref, d, rejected) })
	if err == nil || len(d.Actions) != 0 || m.calls != 2 || task.Status.ModelCalls != 2 || b.Mutations != 0 {
		t.Fatalf("correction escaped budget: calls=%d error=%v", m.calls, err)
	}
}
