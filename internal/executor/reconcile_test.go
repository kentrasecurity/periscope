package executor

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"testing"
	"time"
)

func execution(t *testing.T) (*Executor, *testkit.Memory, *kube.Plan, *time.Time) {
	task, p, a, u, c, now := approved(t)
	p.Spec.Verification.StableWindowSeconds = 1
	p.Spec.Digest, _ = api.DigestPlan(p.Spec)
	a.Spec.PlanDigest = p.Spec.Digest
	b := testkit.NewMemory()
	b.Tasks["demo/fix"] = task
	b.Plans["demo/plan"] = p
	b.ApprovalItems["demo/approve"] = a
	b.PutResource(u)
	return &Executor{Backend: b, Policy: c, Now: func() time.Time { return now }}, b, p, &now
}
func TestResumeAfterWriteDoesNotRepeatPatch(t *testing.T) {
	e, b, p, now := execution(t)
	b.WriteThenError = true
	if err := e.Reconcile(context.Background(), "demo", "fix"); err == nil {
		t.Fatal("expected ambiguous write timeout")
	}
	if b.Mutations != 1 || len(p.Status.Entries) != 1 || p.Status.Entries[0].State != "Pending" {
		t.Fatal("intent not persisted before write")
	}
	b.WriteThenError = false
	for range 3 {
		*now = now.Add(2 * time.Second)
		if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
	}
	if b.Mutations != 1 || p.Status.Phase != "Succeeded" {
		t.Fatalf("repeated write or not verified: %d %s", b.Mutations, p.Status.Phase)
	}
}

func TestResumeAfterWriteDoesNotRepeatRestart(t *testing.T) {
	e, b, p, now := execution(t)
	u := testkit.Resource("apps/v1", "Deployment", "demo", "api", "target-uid", map[string]any{"spec": map[string]any{"replicas": int64(1), "template": map[string]any{"metadata": map[string]any{}, "spec": map[string]any{"containers": []any{map[string]any{"name": "api", "image": "approved"}}}}}, "status": map[string]any{"readyReplicas": int64(1), "availableReplicas": int64(1), "updatedReplicas": int64(1), "observedGeneration": int64(99)}})
	u.Object["spec"].(map[string]any)["selector"] = map[string]any{"matchLabels": map[string]any{"app": "api"}}
	pod := healthyStandalonePod()
	pod.SetName("api-pod")
	pod.SetLabels(map[string]string{"app": "api"})
	linkPods(b, u, pod)
	b.PutResource(pod)
	b.PutResource(u)
	target := api.TargetRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "demo", Name: "api", UID: "target-uid"}
	e.Policy.Capabilities = []policy.Capability{{APIVersion: "apps/v1", Kind: "Deployment", Resource: "deployments", Namespace: "demo", Names: []string{"api"}, Types: []string{"RestartWorkload"}, Risk: "disruptive", RequireApproval: true}}
	b.Tasks["demo/fix"].Spec.TargetRef = target
	p.Spec.TargetRef = target
	p.Spec.Actions = []api.Action{{ID: "restart-1", Type: "RestartWorkload", Target: target}}
	p.Spec.Preconditions.SpecDigest, _ = api.DigestTarget(u)
	p.Spec.PolicyDigest = policy.PolicyDigest(e.Policy)
	p.Spec.Verification = api.Verification{Type: "DeploymentRecovery", TimeoutSeconds: 300, StableWindowSeconds: 1}
	p.Spec.Digest, _ = api.DigestPlan(p.Spec)
	b.ApprovalItems["demo/approve"].Spec.PlanDigest = p.Spec.Digest
	b.WriteThenError = true
	if err := e.Reconcile(context.Background(), "demo", "fix"); err == nil {
		t.Fatal("expected committed write timeout")
	}
	b.WriteThenError = false
	for range 3 {
		*now = now.Add(2 * time.Second)
		if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
	}
	if b.Mutations != 1 || p.Status.Phase != "Succeeded" {
		t.Fatalf("restart duplicated or recovery missing: %d %s", b.Mutations, p.Status.Phase)
	}
}
func TestConcurrentTasksAreFenced(t *testing.T) {
	e, b, p, _ := execution(t)
	b.Claims[api.ClaimKey(p.Spec.TargetRef)] = "another-plan"
	if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if b.Mutations != 0 {
		t.Fatal("conflicting claim ignored")
	}
}
func TestAPISuccessIsNotRecovery(t *testing.T) {
	u := testkit.Resource("apps/v1", "Deployment", "demo", "api", "u", map[string]any{"spec": map[string]any{"replicas": int64(1)}, "status": map[string]any{"readyReplicas": int64(0)}})
	healthy, _, err := CheckResource(u, api.Verification{Type: "DeploymentRecovery"})
	if err != nil || healthy {
		t.Fatal("unhealthy rollout marked success")
	}
}
func TestMissingTaskCancelsUnstartedAction(t *testing.T) {
	e, b, _, _ := execution(t)
	delete(b.Tasks, "demo/fix")
	if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if b.Mutations != 0 {
		t.Fatal("missing task executed")
	}
}
func TestNoApprovalNoExecution(t *testing.T) {
	e, b, _, _ := execution(t)
	b.ApprovalItems = map[string]*kube.Approval{}
	if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if b.Mutations != 0 {
		t.Fatal("unapproved write")
	}
}
func TestPolicyDeniedActionDoesNotExecute(t *testing.T) {
	e, b, _, _ := execution(t)
	e.Policy = policy.Config{}
	_ = e.Reconcile(context.Background(), "demo", "fix")
	if b.Mutations != 0 {
		t.Fatal("policy denied write executed")
	}
}

type terminalStatusConflict struct{ *testkit.Memory }

func (b terminalStatusConflict) SaveTaskStatus(ctx context.Context, t *kube.Task) error {
	if t.Status.Phase == "Succeeded" {
		return fmt.Errorf("status conflict")
	}
	return b.Memory.SaveTaskStatus(ctx, t)
}
func TestTerminalPlanReleasesClaimDespiteTaskStatusConflict(t *testing.T) {
	e, b, p, now := execution(t)
	e.Backend = terminalStatusConflict{b}
	if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Second)
	if err := e.Reconcile(context.Background(), "demo", "fix"); err == nil {
		t.Fatal("expected status conflict")
	}
	if p.Status.Phase != "Succeeded" {
		t.Fatal("plan not terminal")
	}
	if b.Claims[api.ClaimKey(p.Spec.TargetRef)] != "" {
		t.Fatal("terminal plan retained target claim after task status conflict")
	}
}
