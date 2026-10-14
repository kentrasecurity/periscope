package controller

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"strings"
	"testing"
	"time"
)

// diagnosisModel answers every investigation with a diagnosis naming the incident target.
type diagnosisModel struct{ calls int }

func (m *diagnosisModel) Propose(context.Context, llm.Request) (llm.Decision, error) {
	panic("Observe must use the read-only tool loop")
}
func (m *diagnosisModel) Turn(_ context.Context, c llm.Conversation) (llm.TurnResult, error) {
	m.calls++
	if !strings.Contains(c.Messages[0].Text, "Observe mode") {
		panic("observe instruction missing")
	}
	return llm.TurnResult{Decision: &llm.Decision{Diagnosis: "root cause found", Actions: []api.Action{{ID: "fix", Type: "RestartWorkload"}}}}, nil
}

func observeSetup(t *testing.T) (*Investigator, *testkit.Memory, *diagnosisModel, *kube.Task) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	m := &diagnosisModel{}
	i.Model = m
	task := b.Tasks["demo/fix"]
	task.Spec.Mode = "Observe"
	return i, b, m, task
}

func elapse(task *kube.Task) {
	past := time.Now().Add(-time.Hour)
	task.Status.LastCheckedAt = &past
}

func TestObserveDiagnosesOnceAndNeverWrites(t *testing.T) {
	i, b, m, task := observeSetup(t)
	task.Spec.Verification = &api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 60, StableWindowSeconds: 10}
	for range 3 {
		if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
		elapse(task)
	}
	if m.calls != 1 || task.Status.Phase != "Degraded" || task.Status.Healthy == nil || *task.Status.Healthy {
		t.Fatalf("unexpected observe state: calls=%d %+v", m.calls, task.Status)
	}
	if task.Status.Incident == nil || !strings.Contains(task.Status.Incident.Diagnosis, "root cause found") || !strings.Contains(task.Status.Report, "not executed") {
		t.Fatalf("diagnosis not reported: %+v", task.Status)
	}
	if b.Mutations != 0 || len(b.Plans) != 0 || len(b.ApprovalItems) != 0 {
		t.Fatal("Observe created plans, approvals or writes")
	}
	b.Resources["demo/settings"].Object["data"].(map[string]any)["mode"] = "healthy"
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if task.Status.Phase != "Monitoring" || !*task.Status.Healthy || task.Status.Incident != nil || len(task.Status.IncidentHistory) != 1 {
		t.Fatalf("recovery not observed: %+v", task.Status)
	}
	elapse(task)
	b.Resources["demo/settings"].Object["data"].(map[string]any)["mode"] = "broken"
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if m.calls != 2 {
		t.Fatalf("relapse after recovery not diagnosed again: calls=%d", m.calls)
	}
}

func TestObserveScopeMovesPastFirstIncident(t *testing.T) {
	i, b, m, task := observeSetup(t)
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}}}
	for _, name := range []string{"a", "b"} {
		b.PutResource(testkit.Resource("v1", "Pod", "demo", name, name+"-uid", map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "bad"}}}, "status": map[string]any{"phase": "Pending"}}))
	}
	for range 4 {
		if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
		elapse(task)
	}
	if m.calls != 2 {
		t.Fatalf("each incident must be diagnosed exactly once: calls=%d", m.calls)
	}
	if !strings.Contains(task.Status.Report, "demo/Pod/a: root cause") || !strings.Contains(task.Status.Report, "demo/Pod/b: root cause") {
		t.Fatalf("report misses an incident: %s", task.Status.Report)
	}
	delete(b.Resources, "demo/a")
	delete(b.Resources, "demo/b")
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if task.Status.Phase != "Monitoring" || !*task.Status.Healthy || b.Mutations != 0 {
		t.Fatalf("scope recovery not observed: %+v", task.Status)
	}
}

func TestObserveHealthyTargetSpendsNoInference(t *testing.T) {
	i, b, m, task := observeSetup(t)
	task.Spec.Verification = &api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 60, StableWindowSeconds: 10}
	b.Resources["demo/settings"].Object["data"].(map[string]any)["mode"] = "healthy"
	for range 3 {
		if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
		elapse(task)
	}
	if m.calls != 0 || task.Status.Phase != "Monitoring" || !*task.Status.Healthy {
		t.Fatalf("healthy observation spent inference: calls=%d %+v", m.calls, task.Status)
	}
}

func TestObserveKeepsKnownIncidentWhenScanMissesIt(t *testing.T) {
	i, b, m, task := observeSetup(t)
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}}}
	b.PutResource(testkit.Resource("v1", "Pod", "demo", "a", "a-uid", map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "bad"}}}, "status": map[string]any{"phase": "Pending"}}))
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	elapse(task)
	// The next bounded pass covers other kinds only; the Pod is still broken.
	task.Spec.Scope.Resources = []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}, {APIVersion: "batch/v1", Kind: "Job"}}
	found, _ := i.recheckKnown(context.Background(), task, nil)
	if len(found) != 1 {
		t.Fatal("known unhealthy incident dropped when discovery missed it")
	}
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if m.calls != 1 || task.Status.Healthy == nil || *task.Status.Healthy {
		t.Fatalf("missed scan treated as recovery: calls=%d", m.calls)
	}
}

// promptModel records the first prompt of each investigation.
type promptModel struct{ prompts []string }

func (m *promptModel) Propose(context.Context, llm.Request) (llm.Decision, error) {
	panic("Observe must use the read-only tool loop")
}
func (m *promptModel) Turn(_ context.Context, c llm.Conversation) (llm.TurnResult, error) {
	m.prompts = append(m.prompts, c.Messages[0].Text)
	return llm.TurnResult{Decision: &llm.Decision{Diagnosis: "selector typo"}}, nil
}

func TestObserveSendsDetectedSymptoms(t *testing.T) {
	i, b, _, task := observeSetup(t)
	m := &promptModel{}
	i.Model = m
	i.Checker = executor.CheckEvaluator{Reader: b, Pods: b}
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Service"}}}
	b.PutResource(testkit.Resource("v1", "Service", "demo", "web", "web-uid", map[string]any{"spec": map[string]any{"selector": map[string]any{"app": "wbe"}, "ports": []any{map[string]any{"port": int64(80)}}}}))
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if len(m.prompts) != 1 || !strings.Contains(m.prompts[0], `"symptoms"`) || !strings.Contains(m.prompts[0], "Service selector app=wbe matches no Pod or workload template") {
		t.Fatalf("detected symptom not sent to the model: %v", m.prompts)
	}
}
