package controller

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/testkit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"testing"
	"time"
)

func TestHealthyFlapRetainsOriginalIncident(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	task := b.Tasks["demo/fix"]
	task.Status.Incident = &api.IncidentStatus{ID: "original", Attempt: 2}
	task.Status.MonitorVerification = &api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 180, StableWindowSeconds: 120}
	b.Resources["demo/settings"].Object["data"].(map[string]any)["mode"] = "healthy"
	if _, err := i.monitor(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if task.Status.Incident == nil || task.Status.Incident.ID != "original" {
		t.Fatal("healthy sample closed unstable incident")
	}
	b.Resources["demo/settings"].Object["data"].(map[string]any)["mode"] = "broken"
	_, _ = i.monitor(context.Background(), task)
	if task.Status.Incident == nil || task.Status.Incident.ID != "original" || task.Status.Incident.Attempt < 2 {
		t.Fatal("flap lost recovery contract")
	}
}
func TestBlockedIncidentAllowsOtherScopedRepairs(t *testing.T) {
	i, b, m := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}}}
	for _, name := range []string{"a", "b"} {
		b.PutResource(testkit.Resource("v1", "Pod", "demo", name, name, map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "bad"}}}, "status": map[string]any{"phase": "Pending"}}))
	}
	task.Status.ObservedGeneration = 1
	task.Status.Phase = "Blocked"
	task.Status.Budget = api.BudgetStatus{WindowStartedAt: time.Now().UTC()}
	task.Status.Incident = &api.IncidentStatus{ID: "a", Target: api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "a", UID: "a"}, Attempt: 1, OriginalChecks: []api.Check{{ID: "recovery", Type: "PodRecovery", Target: api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "a"}, TimeoutSeconds: 180, StableWindowSeconds: 10}}}
	findings, _, err := i.DiscoverIncidents(context.Background(), *task.Spec.Scope)
	if err != nil {
		t.Fatal(err)
	}
	task.Status.Incident.OriginalChecks = findings[0].Checks
	task.Status.Incident.OriginalChecksDigest, _ = api.Hash(findings[0].Checks)
	task.Status.Incident.FailureFingerprint = findings[0].FailureFingerprint
	_ = i.Reconcile(context.Background(), "demo", "fix")
	if task.Status.Incident == nil || task.Status.Incident.Target.Name != "b" {
		t.Fatal("blocked a remained selected instead of b")
	}
	if m.calls == 0 {
		t.Fatal("blocked first resource starved second investigation")
	}
}
func TestCompletedJobChildPodExcluded(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	job := testkit.Resource("batch/v1", "Job", "demo", "done", "job", map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Complete", "status": "True"}}}})
	b.PutResource(job)
	pod := testkit.Resource("v1", "Pod", "demo", "done-pod", "pod", map[string]any{"status": map[string]any{"phase": "Succeeded"}})
	controller := true
	pod.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "done", UID: types.UID("job"), Controller: &controller}})
	b.PutResource(pod)
	findings, _, err := i.DiscoverIncidents(context.Background(), api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}, {APIVersion: "batch/v1", Kind: "Job"}}})
	if err != nil || len(findings) != 0 {
		t.Fatal("completed Job child treated as broken Pod")
	}
	unfinished := testkit.Resource("batch/v1", "Job", "demo", "unfinished", "unfinished", map[string]any{"spec": map[string]any{"completions": int64(3)}, "status": map[string]any{"succeeded": int64(1)}})
	if jobCompleted(unfinished) {
		t.Fatal("partial Job marked completed")
	}
}
func TestFailedPlanCooldownIndependentOfTaskProjection(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task := b.Tasks["demo/fix"]
	_ = i.Reconcile(context.Background(), "demo", "fix")
	p := b.Plans["demo/"+task.Status.PlanRef.Name]
	p.Status.Phase = "Failed"
	p.Status.Conditions = []api.Condition{{Type: "RemediationVerified", Reason: "VerificationTimedOut", LastTransitionTime: time.Now()}}
	task.Status.Phase = "Verifying"
	cycle := task.Status.Cycle
	_, _ = i.monitor(context.Background(), task)
	if task.Status.Cycle != cycle || task.Status.PlanRef == nil {
		t.Fatal("stale task projection bypassed retry cooldown")
	}
	task.Status.Phase = "Failed"
	task.Status.Incident.Attempt = 3
	b.Resources["demo/settings"].Object["data"].(map[string]any)["mode"] = "changed"
	_, _ = i.monitor(context.Background(), task)
	if task.Status.Cycle != cycle {
		t.Fatal("changed configuration bypassed exhausted attempt budget")
	}
}
func TestCreateRespectsLabelFilteredScope(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "ConfigMap", LabelSelector: "team=a"}}}
	b.Resources["demo/settings"].SetLabels(map[string]string{"team": "a"})
	action := api.Action{ID: "create", Type: "CreateResource", Target: api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "outside"}, Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "outside", "namespace": "demo", "labels": map[string]any{"team": "b"}}}}
	if _, err := i.bindActions(context.Background(), task, api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "settings", UID: "target-uid"}, "baseline", []api.Action{action}); err == nil {
		t.Fatal("excluded creation accepted")
	}
}

var _ *kube.Task

func TestNewIncidentResetsPerInvestigationCountersNotRollingBudget(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}}}
	task.Status.ModelCalls = 5
	task.Status.ToolCalls = 30
	task.Status.Budget = api.BudgetStatus{WindowStartedAt: time.Now(), ModelCalls: 2, ToolCalls: 10}
	b.PutResource(testkit.Resource("v1", "Pod", "demo", "broken", "pod", map[string]any{"status": map[string]any{"phase": "Pending"}}))
	_, err := i.prepareScope(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if task.Status.ModelCalls != 0 || task.Status.ToolCalls != 0 || task.Status.Budget.ModelCalls != 2 {
		t.Fatal("new incident inherited per-investigation exhaustion or reset rolling budget")
	}
}
func TestScopedMissingResourceCanProduceCreatePlan(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}}
	task.Spec.Checks = []api.Check{{ID: "exists", Type: "ResourceExists", Target: api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "missing"}, TimeoutSeconds: 180, StableWindowSeconds: 1}}
	i.Model = fixedModel{decision: llm.Decision{Diagnosis: "reviewed desired resource missing", Actions: []api.Action{{ID: "create", Type: "CreateResource", Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "missing", "namespace": "demo"}, "data": map[string]any{"mode": "healthy"}}}}, Verification: api.Verification{Type: "ResourceExists", TimeoutSeconds: 180, StableWindowSeconds: 1}}}
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if task.Status.PlanRef == nil {
		t.Fatalf("missing resource could not be repaired: %s", task.Status.Report)
	}
}

type temporaryModelFailure struct{}

func (temporaryModelFailure) Propose(context.Context, llm.Request) (llm.Decision, error) {
	return llm.Decision{}, fmt.Errorf("temporary provider failure")
}
func TestKnownTargetProviderFailureRetriesWithOriginalGoal(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task := b.Tasks["demo/fix"]
	task.Spec.Verification = &api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 180, StableWindowSeconds: 10}
	i.Model = temporaryModelFailure{}
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if task.Status.Incident == nil || task.Status.Incident.NextAttemptAt == nil {
		t.Fatal("temporary failure lost known original goal or retry deadline")
	}
	id := task.Status.Incident.ID
	past := time.Now().Add(-time.Second)
	task.Status.Incident.NextAttemptAt = &past
	i.Model = &model{}
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if task.Status.PlanRef == nil || task.Status.Incident.ID != id || task.Status.Incident.Attempt != 2 {
		t.Fatal("remaining known goal did not retry within its bound")
	}
}
