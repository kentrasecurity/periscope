package controller

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/observation"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"testing"
	"time"
)

type fixedModel struct{ decision llm.Decision }

func (f fixedModel) Propose(context.Context, llm.Request) (llm.Decision, error) {
	return f.decision, nil
}

type recoveringProbe struct{ healthy bool }

func (p *recoveringProbe) Check(_ context.Context, t api.TargetRef, _ observation.ProbeRequest) (observation.ProbeResult, error) {
	return observation.ProbeResult{Success: p.healthy, Vantage: "pod:" + t.UID, ObservedAt: time.Now().UTC()}, nil
}
func TestNetworkFailureReinvestigatesScopedService(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	pod := testkit.Resource("v1", "Pod", "demo", "app", "poduid", map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "known"}}}, "status": map[string]any{"phase": "Pending"}})
	b.PutResource(pod)
	service := testkit.Resource("v1", "Service", "demo", "service", "serviceuid", map[string]any{"spec": map[string]any{"ports": []any{map[string]any{"port": int64(80), "targetPort": int64(9999)}}}})
	b.PutResource(service)
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}}
	task.Spec.Mode = "HumanApproved"
	task.Spec.Checks = []api.Check{{ID: "reachable", Type: "HTTP", Target: api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "app"}, Endpoint: "http://service.demo/healthz", Vantage: "monitored-pod", TimeoutSeconds: 180, StableWindowSeconds: 1}}
	probe := &recoveringProbe{}
	i.Checker.Probe = probe
	i.Model = fixedModel{decision: llm.Decision{Diagnosis: "wrong Service port", Actions: []api.Action{{ID: "port", Type: "PatchResource", Target: api.TargetRef{APIVersion: "v1", Kind: "Service", Namespace: "demo", Name: "service"}, Patch: []api.PatchOp{{Op: "replace", Path: "/spec/ports/0/targetPort", Value: float64(8080)}}}}, Verification: api.Verification{Type: "PodRecovery", TimeoutSeconds: 180, StableWindowSeconds: 1}}}
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if task.Status.PlanRef == nil || task.Status.ApprovalRef == nil {
		t.Fatalf("no generated human review: %s %s", task.Status.Phase, task.Status.Report)
	}
	approval := b.ApprovalItems["demo/"+task.Status.ApprovalRef.Name]
	if approval.Spec.Decision != "Pending" {
		t.Fatal("human review bypassed")
	}
	now := time.Now().UTC()
	ex := executor.Executor{Backend: b, Policy: i.Policy, Checker: i.Checker, Now: func() time.Time { return now }}
	if err := ex.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if b.Mutations != 0 {
		t.Fatal("write before approval")
	}
	approval.Spec.Decision = "Approve"
	if err := ex.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	plan := b.Plans["demo/"+task.Status.PlanRef.Name]
	if b.Mutations != 1 || plan.Status.Phase != "Verifying" || executor.ChecksHealthy(plan.Status.CheckResults) {
		t.Fatalf("API success became network recovery: %d %s", b.Mutations, plan.Status.Phase)
	}
	probe.healthy = true
	for range 2 {
		now = now.Add(2 * time.Second)
		if err := ex.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
	}
	if plan.Status.Phase != "Succeeded" || b.Mutations != 1 {
		t.Fatal("real correct-vantage recovery was not verified")
	}
}
func TestGenericCustomResourceRepairWithoutCatalog(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	widget := testkit.Resource("apps.acme.test/v1", "Widget", "demo", "widget", "widgetuid", map[string]any{"spec": map[string]any{"port": int64(9999)}})
	b.PutResource(widget)
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{APIVersion: "apps.acme.test/v1", Kind: "Widget", Namespace: "demo", Name: "widget"}
	task.Spec.Mode = "Automatic"
	task.Spec.Objective = "Keep Widget port equal to the reviewed desired configuration 8080"
	task.Spec.Verification = &api.Verification{Type: "FieldEquals", Path: "/spec/port", Expected: float64(8080), TimeoutSeconds: 180, StableWindowSeconds: 1}
	i.Model = fixedModel{decision: llm.Decision{Diagnosis: "incorrect Widget configuration", Actions: []api.Action{{ID: "repair-widget", Type: "PatchResource", Patch: []api.PatchOp{{Op: "replace", Path: "/spec/port", Value: float64(8080)}}}}, Verification: *task.Spec.Verification}}
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if task.Status.PlanRef == nil || task.Status.ApprovalRef == nil {
		t.Fatalf("no generic plan: %s", task.Status.Report)
	}
	approval := b.ApprovalItems["demo/"+task.Status.ApprovalRef.Name]
	if approval.Spec.Decision != "Approve" {
		t.Fatal("automatic mode did not approve checked plan")
	}
	now := time.Now().UTC()
	ex := executor.Executor{Backend: b, Policy: i.Policy, Now: func() time.Time { return now }}
	for range 3 {
		if err := ex.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Second)
	}
	if b.Plans["demo/"+task.Status.PlanRef.Name].Status.Phase != "Succeeded" || b.Mutations != 1 {
		t.Fatal("custom resource repair was bound to a built-in kind catalog")
	}
}
