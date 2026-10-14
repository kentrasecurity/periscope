package controller

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"testing"
	"time"
)

type model struct {
	calls int
	bad   bool
}

func (m *model) Propose(_ context.Context, _ llm.Request) (llm.Decision, error) {
	m.calls++
	a := api.Action{ID: "repair", Type: "PatchResource", Patch: []api.PatchOp{{Op: "replace", Path: "/data/mode", Value: "healthy"}}}
	if m.bad {
		a.Target = api.TargetRef{APIVersion: "v1", Kind: "Secret", Namespace: "other", Name: "key"}
	}
	return llm.Decision{Diagnosis: "mode is broken", Risk: "low", Actions: []api.Action{a}, Verification: api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 300, StableWindowSeconds: 120}}, nil
}
func setup(t *testing.T) (*Investigator, *testkit.Memory, *model) {
	t.Helper()
	b := testkit.NewMemory()
	target := testkit.Resource("v1", "ConfigMap", "demo", "settings", "target-uid", map[string]any{"data": map[string]any{"mode": "broken"}})
	b.PutResource(target)
	// Tests exercise incident handling directly; grace periods have their own tests.
	task := b.PutTask("demo", "fix", "task-uid", api.TaskSpec{TargetRef: api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Name: "settings"}, Mode: "HumanApproved", Objective: "fix mode", Limits: api.DefaultLimits(), Monitoring: &api.Monitoring{IntervalSeconds: 30, GracePeriodSeconds: new(int)}})
	task.Object.SetCreationTimestamp(testkit.Timestamp(time.Now()))
	c := policy.Config{CoordinationNamespace: "demo", Namespaces: []string{"demo"}, ReadRules: []policy.ReadRule{{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Resource: "configmaps", Names: []string{"settings"}, DataKeys: []string{"mode"}}}, Capabilities: []policy.Capability{{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Resource: "configmaps", Names: []string{"settings"}, Types: []string{"PatchResource"}, Paths: map[string]policy.ValueRule{"/data/mode": {Values: []any{"healthy"}}}, Risk: "low", RequireApproval: true}}}
	m := &model{}
	return &Investigator{Backend: b, Model: m, Policy: c, Collector: evidence.Collector{Reader: b, Policy: c, MaxToolCalls: 30}}, b, m
}
func TestNoMutationBeforeApproval(t *testing.T) {
	i, b, _ := setup(t)
	if e := i.Reconcile(context.Background(), "demo", "fix"); e != nil {
		t.Fatal(e)
	}
	task, _ := b.GetTask(context.Background(), "demo", "fix")
	if task.Status.Phase != "AwaitingApproval" || task.Status.PlanRef == nil || b.Mutations != 0 {
		t.Fatalf("unsafe phase %s", task.Status.Phase)
	}
}
func TestWatchRelistDoesNotDuplicatePlan(t *testing.T) {
	i, b, m := setup(t)
	for range 3 {
		if e := i.Reconcile(context.Background(), "demo", "fix"); e != nil {
			t.Fatal(e)
		}
	}
	if m.calls != 1 || len(b.Plans) != 1 {
		t.Fatal("duplicate plan/model calls")
	}
}
func TestTaskGenerationInvalidatesOldWork(t *testing.T) {
	i, b, _ := setup(t)
	_ = i.Reconcile(context.Background(), "demo", "fix")
	task, _ := b.GetTask(context.Background(), "demo", "fix")
	task.Object.SetGeneration(2)
	task.Spec.Objective = "re-evaluate"
	if e := i.Reconcile(context.Background(), "demo", "fix"); e != nil {
		t.Fatal(e)
	}
	if len(b.Plans) != 2 || task.Status.ObservedGeneration != 2 {
		t.Fatal("new intent reused old plan")
	}
}
func TestModelCannotCreateApproval(t *testing.T) {
	i, b, m := setup(t)
	m.bad = true
	_ = i.Reconcile(context.Background(), "demo", "fix")
	if len(b.Plans) != 0 || b.Mutations != 0 {
		t.Fatal("model escaped scope")
	}
}
func TestMissingEvidenceDoesNotFabricateSuccess(t *testing.T) {
	i, b, _ := setup(t)
	b.ReadDenied = true
	_ = i.Reconcile(context.Background(), "demo", "fix")
	task, _ := b.GetTask(context.Background(), "demo", "fix")
	if task.Status.Phase == "Succeeded" || len(b.Plans) != 0 {
		t.Fatal("denied evidence fabricated success")
	}
}
func TestBudgetAndProviderFailureBounded(t *testing.T) {
	i, b, m := setup(t)
	m.bad = true
	task, _ := b.GetTask(context.Background(), "demo", "fix")
	task.Spec.Limits.MaxModelCalls = 1
	for range 4 {
		_ = i.Reconcile(context.Background(), "demo", "fix")
	}
	if m.calls > 1 {
		t.Fatal("model budget exceeded")
	}
}
