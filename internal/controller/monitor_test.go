package controller

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/observation"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"testing"
	"time"
)

func TestHealthyPollingAvoidsModelAndReopensAfterRelapse(t *testing.T) {
	i, b, m := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task, _ := b.GetTask(context.Background(), "demo", "fix")
	task.Spec.Verification = &api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 300, StableWindowSeconds: 1}
	u := b.Resources["demo/settings"]
	u.Object["data"].(map[string]any)["mode"] = "healthy"
	for range 3 {
		if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
	}
	if m.calls != 0 || task.Status.LastCheckedAt == nil || task.Status.Healthy == nil || !*task.Status.Healthy {
		t.Fatal("healthy polling called model or did not monitor")
	}
	u.Object["data"].(map[string]any)["mode"] = "broken"
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if m.calls != 1 || task.Status.Phase != "AwaitingApproval" || len(b.ApprovalItems) != 1 {
		t.Fatal("relapse did not create fresh pending review")
	}
	for _, a := range b.ApprovalItems {
		if a.Spec.Decision != "Pending" {
			t.Fatal("human task auto-approved")
		}
	}
	_ = evidence.Redact
}
func TestAutomaticCreatesCheckedApprovalAndSuspendStops(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task, _ := b.GetTask(context.Background(), "demo", "fix")
	task.Spec.Mode = "Automatic"
	task.Spec.Verification = &api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 300, StableWindowSeconds: 1}
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	for _, a := range b.ApprovalItems {
		if a.Spec.Decision != "Approve" {
			t.Fatal("automatic task did not approve")
		}
	}
	if len(b.ApprovalItems) != 1 {
		t.Fatal("automatic approval absent")
	}
	task.Spec.Suspend = true
	before := task.Status.LastCheckedAt
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if before != task.Status.LastCheckedAt {
		t.Fatal("suspended task polled")
	}
	_ = kube.Task{}
}
func TestWaitingHumanKeepsPollingAndExternalRepairInvalidatesPlan(t *testing.T) {
	i, b, m := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task, _ := b.GetTask(context.Background(), "demo", "fix")
	task.Spec.Verification = &api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 300, StableWindowSeconds: 1}
	_ = i.Reconcile(context.Background(), "demo", "fix")
	for range 3 {
		_ = i.Reconcile(context.Background(), "demo", "fix")
	}
	if m.calls != 1 || b.Mutations != 0 || task.Status.LastCheckedAt == nil {
		t.Fatal("waiting either stopped polling or called model/wrote")
	}
	b.Resources["demo/settings"].Object["data"].(map[string]any)["mode"] = "healthy"
	_ = i.Reconcile(context.Background(), "demo", "fix")
	if task.Status.PlanRef != nil || task.Status.Healthy == nil || !*task.Status.Healthy || b.Mutations != 0 {
		t.Fatal("externally resolved pending plan still executable")
	}
}
func TestChangedTargetCreatesNewPlanAndOldApprovalCannotFollow(t *testing.T) {
	i, b, m := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	_ = i.Reconcile(context.Background(), "demo", "fix")
	task, _ := b.GetTask(context.Background(), "demo", "fix")
	old := *task.Status.PlanRef
	b.Resources["demo/settings"].SetUID("replacement-uid")
	_ = i.Reconcile(context.Background(), "demo", "fix")
	if task.Status.PlanRef == nil || task.Status.PlanRef.UID == old.UID || m.calls != 2 || task.Status.Cycle != 1 {
		t.Fatal("replacement reused stale proposal")
	}
}
func TestLearnedGenericVerificationSurvivesClearedAuthorization(t *testing.T) {
	i, b, m := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	_ = i.Reconcile(context.Background(), "demo", "fix")
	b.Resources["demo/settings"].Object["data"].(map[string]any)["mode"] = "healthy"
	for range 3 {
		_ = i.Reconcile(context.Background(), "demo", "fix")
	}
	task, _ := b.GetTask(context.Background(), "demo", "fix")
	if m.calls != 1 || task.Status.Healthy == nil || !*task.Status.Healthy {
		t.Fatal("healthy generic target lost learned verification and called model again")
	}
}
func TestGeneratedApprovalFitsSerializedCreationTimestamp(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	_ = i.Reconcile(context.Background(), "demo", "fix")
	for _, a := range b.ApprovalItems {
		born := a.Object.GetCreationTimestamp().Time.Truncate(time.Second)
		if a.Spec.ExpiresAt.After(born.Add(30 * time.Minute)) {
			t.Fatal("fractional expiry exceeds whole-second creation bound")
		}
	}
}

// unhealthyMetric answers every query with a value that fails its check.
type unhealthyMetric struct{}

func (unhealthyMetric) Definition() observation.ToolDefinition {
	return observation.ToolDefinition{Name: "query_prometheus"}
}
func (unhealthyMetric) Call(context.Context, api.Scope, observation.ToolCall) (observation.ToolResult, error) {
	return observation.ToolResult{Content: []byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"1"]}]}}`)}, nil
}

func TestPrometheusCheckOnDeploymentProducesValidPlan(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	i.Checker = executor.CheckEvaluator{Reader: b, Pods: b, Metrics: unhealthyMetric{}}
	ref := api.TargetRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "demo", Name: "worker"}
	b.PutResource(testkit.Resource("apps/v1", "Deployment", "demo", "worker", "worker-uid", map[string]any{"spec": map[string]any{"replicas": int64(1), "template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "worker", "image": "busybox", "resources": map[string]any{"limits": map[string]any{"cpu": "10m"}}}}}}}}))
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}}
	task.Spec.Checks = []api.Check{{ID: "throttling", Type: "Prometheus", Target: ref, Query: "throttled > bool 0.25", Expected: "0", TimeoutSeconds: 600, StableWindowSeconds: 60}}
	ref.UID = "worker-uid"
	i.Model = fixedModel{decision: llm.Decision{Diagnosis: "CPU limit too low", Actions: []api.Action{{ID: "cpu", Type: "PatchResource", Target: ref, Patch: []api.PatchOp{{Op: "replace", Path: "/spec/template/spec/containers/0/resources/limits/cpu", Value: "200m"}}}}, Verification: api.Verification{Type: "ResourceHealthy", TimeoutSeconds: 600, StableWindowSeconds: 60}}}
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if task.Status.PlanRef == nil {
		t.Fatalf("metric incident on a Deployment produced no plan: %s %s", task.Status.Phase, task.Status.Report)
	}
}
