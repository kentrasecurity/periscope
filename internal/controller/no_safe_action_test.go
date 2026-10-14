package controller

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"strings"
	"testing"
	"time"
)

// noActionModel finds no safe repair, as for a missing Secret.
type noActionModel struct{ calls int }

func (m *noActionModel) Propose(context.Context, llm.Request) (llm.Decision, error) {
	panic("RBAC tasks use the tool loop")
}
func (m *noActionModel) Turn(context.Context, llm.Conversation) (llm.TurnResult, error) {
	m.calls++
	return llm.TurnResult{Decision: &llm.Decision{Diagnosis: "Secret db-credentials does not exist; creating Secrets is outside the task"}}, nil
}

func waitingPod(reason string) map[string]any {
	return map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "app:1"}}},
		"status": map[string]any{"phase": "Pending", "containerStatuses": []any{map[string]any{"name": "app", "image": "app:1", "ready": false, "state": map[string]any{"waiting": map[string]any{"reason": reason}}}}}}
}

func TestNoSafeActionHoldsIncidentUntilFailureChanges(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	m := &noActionModel{}
	i.Model = m
	task := b.Tasks["demo/fix"]
	task.Spec.Mode = "Automatic"
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}}}
	b.PutResource(testkit.Resource("v1", "Pod", "demo", "app", "app-uid", waitingPod("CreateContainerConfigError")))
	for range 5 {
		if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
		elapse(task)
		for n := range task.Status.IncidentHistory { // cooldowns must not matter
			past := time.Now().Add(-time.Hour)
			task.Status.IncidentHistory[n].NextAttemptAt = &past
		}
	}
	if m.calls != 1 || b.Mutations != 0 || len(b.Plans) != 0 {
		t.Fatalf("unfixable incident re-investigated or written: calls=%d mutations=%d", m.calls, b.Mutations)
	}
	held := task.Status.IncidentHistory[len(task.Status.IncidentHistory)-1]
	if held.Outcome != api.IncidentNoSafeAction || !strings.Contains(held.Diagnosis, "db-credentials") {
		t.Fatalf("hold reason not recorded: %+v", held)
	}
	if !strings.Contains(task.Status.Report, "owner action") || !strings.Contains(task.Status.Report, "demo/v1/Pod/app: Secret db-credentials") {
		t.Fatalf("report does not explain the hold: %s", task.Status.Report)
	}
	b.PutResource(testkit.Resource("v1", "Pod", "demo", "app", "app-uid", waitingPod("ImagePullBackOff")))
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if m.calls != 2 {
		t.Fatalf("changed failure not investigated: calls=%d", m.calls)
	}
}

func TestUnretryableRepairFailureDoesNotStallScope(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	m := &noActionModel{}
	i.Model = m
	task := b.Tasks["demo/fix"]
	task.Spec.Mode = "Automatic"
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}}}
	task.Status.ObservedGeneration = 1
	b.PutResource(testkit.Resource("v1", "Pod", "demo", "a", "a-uid", waitingPod("CreateContainerConfigError")))
	b.PutResource(testkit.Resource("v1", "Pod", "demo", "b", "b-uid", waitingPod("ImagePullBackOff")))
	task.Status.Phase = "Failed"
	task.Status.Incident = &api.IncidentStatus{ID: "a", Target: api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "a", UID: "a-uid"}, Attempt: 1}
	task.Status.Conditions = []api.Condition{{Type: "RemediationVerified", Status: "False", Reason: "PolicyDenied", Message: "capability no longer granted"}}
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if len(task.Status.IncidentHistory) == 0 || task.Status.IncidentHistory[0].Outcome != api.IncidentRepairFailed || !strings.Contains(task.Status.IncidentHistory[0].Diagnosis, "PolicyDenied") {
		t.Fatalf("unretryable failure not held for the owner: %+v", task.Status.IncidentHistory)
	}
	if m.calls == 0 {
		t.Fatalf("scope stalled behind an unretryable failure: phase=%s report=%s", task.Status.Phase, task.Status.Report)
	}
}
