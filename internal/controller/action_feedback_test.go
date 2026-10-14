package controller

import (
	"context"
	"testing"

	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/llm"
)

func TestMalformedReplacementIdentityCanBeCorrectedWithinBudget(t *testing.T) {
	for _, budget := range []int{1, 2} {
		t.Run(string(rune('0'+budget)), func(t *testing.T) {
			i, b, _ := setup(t)
			i.Policy.Authorization = "RBAC"
			i.Collector.Policy = i.Policy
			task := b.Tasks["demo/fix"]
			task.Spec.Limits.MaxModelCalls = budget
			task.Spec.Verification = &api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 60, StableWindowSeconds: 1}
			bad := llm.Decision{Diagnosis: "replace configuration", Actions: []api.Action{
				{ID: "delete", Type: "DeleteResource"},
				{ID: "create", Type: "CreateResource", Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "wrong-name", "namespace": "demo"}, "data": map[string]any{"mode": "healthy"}}},
			}, Verification: *task.Spec.Verification}
			good := bad
			good.Actions = append([]api.Action(nil), bad.Actions...)
			good.Actions[1].Object = map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "settings", "namespace": "demo"}, "data": map[string]any{"mode": "healthy"}}
			m := &retryToolModel{proposal: bad, corrected: good}
			i.Model = m
			if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
				t.Fatal(err)
			}
			if budget == 1 && (task.Status.Phase != "Blocked" || len(b.Plans) != 0) {
				t.Fatal("invalid proposal escaped exhausted budget")
			}
			if budget == 2 && (m.calls != 2 || task.Status.Phase != "AwaitingApproval" || len(b.Plans) != 1) {
				t.Fatalf("identity correction failed: calls=%d phase=%s report=%s", m.calls, task.Status.Phase, task.Status.Report)
			}
			if b.Mutations != 0 || task.Status.ModelCalls != budget {
				t.Fatal("validation executed writes or bypassed model budget")
			}
		})
	}
}
