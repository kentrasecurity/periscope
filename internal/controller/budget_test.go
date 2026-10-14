package controller

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"testing"
	"time"
)

func TestRollingBudgetReplenishesWithoutLosingIncidentHistory(t *testing.T) {
	now := time.Now().UTC()
	limits := api.DefaultHealingLimits()
	limits.MaxModelCallsPerWindow = 1
	status, err := ReserveBudget(api.BudgetStatus{}, limits, now, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveBudget(status, limits, now.Add(time.Second), 1, 0); err == nil {
		t.Fatal("budget overrun")
	}
	next, err := ReserveBudget(status, limits, now.Add(time.Duration(limits.WindowSeconds)*time.Second), 1, 0)
	if err != nil || next.ModelCalls != 1 || !next.WindowStartedAt.After(status.WindowStartedAt) {
		t.Fatal("window did not replenish")
	}
}

func TestCooldownPreventsIneffectiveRepairLoop(t *testing.T) {
	i, b, _ := setup(t)
	task := b.Tasks["demo/fix"]
	task.Status.Incident = &api.IncidentStatus{Attempt: 3}
	p := &kube.Plan{Status: api.PlanStatus{Phase: "Failed", Conditions: []api.Condition{{Type: "RemediationVerified", Reason: "VerificationTimedOut", LastTransitionTime: time.Now().Add(-time.Hour)}}}}
	if retry, _, _ := RetryDecision(task, p, time.Now()); retry {
		t.Fatal("exhausted incident repeated")
	}
	task.Status.Incident.Attempt = 1
	p.Status.Conditions[0].LastTransitionTime = time.Now()
	if retry, _, _ := RetryDecision(task, p, time.Now()); retry {
		t.Fatal("cooldown ignored")
	}
	_ = i
}
func TestExhaustedIncidentDoesNotStarveNamespace(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}}
	task.Status.ObservedGeneration = 1
	task.Status.Phase = "Failed"
	task.Status.Incident = &api.IncidentStatus{ID: "held", Target: api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "settings", UID: "target-uid"}, Attempt: 3, OriginalChecks: []api.Check{{ID: "repair", Type: "FieldEquals", Target: api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "settings"}, Path: "/data/mode", Expected: "healthy"}}}
	task.Status.MonitorVerification = &api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 180, StableWindowSeconds: 10}
	if _, err := i.monitor(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if task.Status.Incident != nil || len(task.Status.IncidentHistory) != 1 {
		t.Fatal("held incident starves namespace scanning")
	}
}
