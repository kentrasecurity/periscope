package controller

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"strings"
	"testing"
	"time"
)

func setGrace(task *kube.Task, seconds int) { task.Spec.Monitoring.GracePeriodSeconds = &seconds }

func pendingPod() map[string]any {
	return map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "app:1"}}}, "status": map[string]any{"phase": "Pending"}}
}

func podScope(task *kube.Task) {
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}}}
}

func TestObserveWaitsOutGracePeriodBeforeDiagnosing(t *testing.T) {
	i, b, m, task := observeSetup(t)
	setGrace(task, 60)
	podScope(task)
	b.PutResource(testkit.Resource("v1", "Pod", "demo", "starting", "pod-uid", pendingPod()))
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if m.calls != 0 || task.Status.Incident != nil || len(task.Status.Suspects) != 1 || !strings.Contains(task.Status.Report, "grace period") {
		t.Fatalf("transient failure diagnosed before its grace period: calls=%d %+v", m.calls, task.Status)
	}
	task.Status.Suspects[0].Since = time.Now().Add(-2 * time.Minute)
	elapse(task)
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if m.calls != 1 || task.Status.Incident == nil || task.Status.Incident.Target.Name != "starting" {
		t.Fatalf("persistent failure not diagnosed after grace: calls=%d %+v", m.calls, task.Status)
	}
	// Recovery forgets the suspect, so a relapse waits out the grace period again.
	delete(b.Resources, "demo/starting")
	elapse(task)
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if len(task.Status.Suspects) != 0 || task.Status.Incident != nil {
		t.Fatalf("recovered suspect retained: %+v", task.Status)
	}
	b.PutResource(testkit.Resource("v1", "Pod", "demo", "starting", "pod-uid-2", pendingPod()))
	elapse(task)
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if m.calls != 1 || len(task.Status.Suspects) != 1 {
		t.Fatalf("relapse skipped the grace period: calls=%d %+v", m.calls, task.Status)
	}
}

func TestScopedHealingWaitsOutGracePeriodBeforePlanning(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task := b.Tasks["demo/fix"]
	setGrace(task, 60)
	podScope(task)
	b.PutResource(testkit.Resource("v1", "Pod", "demo", "rolling", "pod-uid", pendingPod()))
	done, err := i.prepareScope(context.Background(), task)
	if err != nil || !done || task.Status.Incident != nil || len(task.Status.Suspects) != 1 {
		t.Fatalf("incident opened inside grace period: done=%t err=%v %+v", done, err, task.Status)
	}
	if task.Status.Healthy == nil || !*task.Status.Healthy || !strings.Contains(task.Status.Report, "grace period") {
		t.Fatalf("grace state not reported: %+v", task.Status)
	}
	task.Status.Suspects[0].Since = time.Now().Add(-2 * time.Minute)
	task.Status.LastScopeScanAt = nil
	done, err = i.prepareScope(context.Background(), task)
	if err != nil || done || task.Status.Incident == nil || task.Status.Incident.Target.Name != "rolling" {
		t.Fatalf("persistent failure not promoted to incident: done=%t err=%v %+v", done, err, task.Status)
	}
}

func TestSingleTargetGracePeriodStartsOneFreshCycle(t *testing.T) {
	i, b, m := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task := b.Tasks["demo/fix"]
	setGrace(task, 60)
	task.Spec.Verification = &api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 300, StableWindowSeconds: 1}
	mode := b.Resources["demo/settings"].Object["data"].(map[string]any)
	mode["mode"] = "healthy"
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	cycle := task.Status.Cycle
	mode["mode"] = "broken"
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if m.calls != 0 || len(b.Plans) != 0 || task.Status.Phase != "Monitoring" || len(task.Status.Suspects) != 1 || task.Status.Cycle != cycle+1 {
		t.Fatalf("failure inside grace period: calls=%d plans=%d cycle %d->%d %+v", m.calls, len(b.Plans), cycle, task.Status.Cycle, task.Status)
	}
	task.Status.Suspects[0].Since = time.Now().Add(-2 * time.Minute)
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if len(b.Plans) != 1 || task.Status.PlanRef == nil || task.Status.Cycle != cycle+1 {
		t.Fatalf("persistent failure not investigated in the new cycle: cycle %d->%d %+v", cycle, task.Status.Cycle, task.Status)
	}
}

func TestSuspectsAreForgottenOnlyWhenTheirKindWasListed(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	task := b.Tasks["demo/fix"]
	setGrace(task, 60)
	first := time.Now().Add(-30 * time.Second)
	recovered := api.Suspect{Target: api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "recovered", UID: "recovered"}, Since: first}
	unlisted := api.Suspect{Target: api.TargetRef{APIVersion: "custom.test/v1", Kind: "Widget", Namespace: "demo", Name: "w", UID: "w"}, Since: first}
	task.Status.Suspects = []api.Suspect{recovered, unlisted}
	// One kind is unreadable on every pass, as with auto-discovered kinds the
	// RBAC presets do not grant; recovery in readable kinds is still seen.
	i.Collector.Reader = unreadableWidgets{b}
	_, _, covered, err := i.discoverIncidents(context.Background(), api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}, {APIVersion: "custom.test/v1", Kind: "Widget"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	debounce(task, nil, covered, time.Now())
	if len(task.Status.Suspects) != 1 || task.Status.Suspects[0].Target.Name != "w" || !task.Status.Suspects[0].Since.Equal(first) {
		t.Fatalf("expected only the unlisted kind's suspect to be kept: %+v", task.Status.Suspects)
	}
}

type unreadableWidgets struct{ *testkit.Memory }

func (r unreadableWidgets) List(ctx context.Context, version, kind, ns, selector string) ([]*unstructured.Unstructured, error) {
	if kind == "Widget" {
		return nil, fmt.Errorf("forbidden")
	}
	return r.Memory.List(ctx, version, kind, ns, selector)
}

func TestHealthyIncidentTargetKeepsOtherScopedSuspects(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task := b.Tasks["demo/fix"]
	setGrace(task, 60)
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}}
	target := api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "settings", UID: "target-uid"}
	check := api.Check{ID: "mode", Type: "FieldEquals", Target: target, Path: "/data/mode", Expected: "broken", TimeoutSeconds: 60, StableWindowSeconds: 30}
	digest, _ := api.Hash([]api.Check{check})
	task.Status.Incident = &api.IncidentStatus{ID: "incident", Target: target, Attempt: 1, OriginalChecks: []api.Check{check}, OriginalChecksDigest: digest}
	other := api.Suspect{Target: api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "other", UID: "other"}, Since: time.Now().Add(-30 * time.Second)}
	task.Status.Suspects = []api.Suspect{other}
	if _, err := i.monitor(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if task.Status.Healthy == nil || !*task.Status.Healthy || len(task.Status.Suspects) != 1 {
		t.Fatalf("healthy incident target wiped other resources' grace timers: %+v", task.Status)
	}
}
