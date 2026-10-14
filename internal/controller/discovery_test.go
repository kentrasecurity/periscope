package controller

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/testkit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNamespaceDiscoveryFindsStandalonePodAndSkipsCompletedJob(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	b.PutResource(testkit.Resource("v1", "Pod", "demo", "bad-pod", "pod-uid", map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "bad"}}}, "status": map[string]any{"phase": "Pending"}}))
	b.PutResource(testkit.Resource("batch/v1", "Job", "demo", "done", "job-uid", map[string]any{"status": map[string]any{"succeeded": int64(1)}}))
	findings, _, err := i.DiscoverIncidents(context.Background(), api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}, {APIVersion: "batch/v1", Kind: "Job"}}})
	if err != nil || len(findings) != 1 || findings[0].Target.Name != "bad-pod" {
		t.Fatalf("unexpected incidents: %+v %v", findings, err)
	}
}
func TestHealthyScopePollsWithoutInference(t *testing.T) {
	i, b, m := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "batch/v1", Kind: "Job"}}}
	b.PutResource(testkit.Resource("batch/v1", "Job", "demo", "done", "job", map[string]any{"status": map[string]any{"succeeded": int64(1)}}))
	for range 2 {
		if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
	}
	if m.calls != 0 || task.Status.LastCheckedAt == nil || task.Status.Healthy == nil || !*task.Status.Healthy {
		t.Fatal("healthy scope spent inference or lacked periodic check")
	}
}

func TestManagedPodRepairTargetsOwnerInsideScope(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	owner := testkit.Resource("apps/v1", "Deployment", "demo", "app", "owner", map[string]any{"spec": map[string]any{"replicas": int64(1)}, "status": map[string]any{"readyReplicas": int64(0)}})
	b.PutResource(owner)
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}}}
	primary := api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "pod", UID: "pod"}
	action := api.Action{ID: "restart", Type: "RestartWorkload", Target: api.TargetRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "demo", Name: "app"}}
	if _, err := i.bindActions(context.Background(), task, primary, "baseline", []api.Action{action}); err == nil {
		t.Fatal("out of scope owner became writable")
	}
	task.Spec.Scope.Resources = append(task.Spec.Scope.Resources, api.ResourceSelector{APIVersion: "apps/v1", Kind: "Deployment"})
	bindings, err := i.bindActions(context.Background(), task, primary, "baseline", []api.Action{action})
	if err != nil || len(bindings) != 2 || bindings[1].Target.UID != "owner" {
		t.Fatalf("owner binding: %v %v", bindings, err)
	}
}
func TestUnsupportedScopedResourceReportsHealthGap(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	b.PutResource(testkit.Resource("custom.test/v1", "Widget", "demo", "widget", "uid", map[string]any{"spec": map[string]any{"port": int64(8080)}}))
	findings, gaps, err := i.DiscoverIncidents(context.Background(), api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "custom.test/v1", Kind: "Widget"}}})
	if err != nil || len(findings) != 0 || len(gaps) == 0 {
		t.Fatal("unknown health semantics silently reported healthy")
	}
}

type largeDiscovery struct{ *testkit.Memory }

func (largeDiscovery) NamespacedResources(context.Context) ([]api.ResourceSelector, error) {
	resources := []api.ResourceSelector{}
	for n := 0; n < 79; n++ {
		resources = append(resources, api.ResourceSelector{APIVersion: "custom.test/v1", Kind: fmt.Sprintf("Kind%d", n)})
	}
	return append(resources, api.ResourceSelector{APIVersion: "v1", Kind: "Pod"}), nil
}
func TestBoundedDiscoveryEventuallyChecksEveryNamespace(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Policy.Namespaces = []string{"demo", "y", "z"}
	i.Collector.Reader = largeDiscovery{b}
	task := b.Tasks["demo/fix"]
	task.Spec.TargetRef = api.TargetRef{}
	task.Spec.Scope = &api.Scope{Namespaces: []string{"demo", "y", "z"}}
	b.PutResource(testkit.Resource("v1", "Pod", "z", "broken", "pod", map[string]any{"status": map[string]any{"phase": "Pending"}}))
	for range 3 {
		_, err := i.prepareScope(context.Background(), task)
		if err != nil {
			t.Fatal(err)
		}
	}
	if task.Status.Incident == nil || task.Status.Incident.Target.Namespace != "z" {
		t.Fatal("bounded first-page scanning starved third namespace")
	}
}

type coreDiscovery struct{ *testkit.Memory }

func (coreDiscovery) NamespacedResources(context.Context) ([]api.ResourceSelector, error) {
	return []api.ResourceSelector{{APIVersion: "v1", Kind: "ConfigMap"}, {APIVersion: "v1", Kind: "Service"}, {APIVersion: "v1", Kind: "Pod"}, {APIVersion: "apps/v1", Kind: "Deployment"}}, nil
}

func TestDiscoveryFindsOrphanedServiceWithoutConfigGaps(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Reader = coreDiscovery{b}
	b.PutResource(testkit.Resource("v1", "Service", "demo", "web", "svc", map[string]any{"spec": map[string]any{"selector": map[string]any{"app": "web"}}}))
	scope := api.Scope{Namespaces: []string{"demo"}}
	findings, gaps, err := i.DiscoverIncidents(context.Background(), scope)
	if err != nil || len(gaps) != 0 || len(findings) != 1 || findings[0].Target.Kind != "Service" {
		t.Fatalf("orphaned Service not found or config kinds reported as gaps: %+v %v %v", findings, gaps, err)
	}
	pod := testkit.Resource("v1", "Pod", "demo", "web-1", "pod", map[string]any{"metadata": map[string]any{"name": "web-1", "namespace": "demo", "uid": "pod", "labels": map[string]any{"app": "web"}}, "spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "web"}}}, "status": map[string]any{"phase": "Running", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}, "containerStatuses": []any{map[string]any{"name": "app", "image": "web", "ready": true, "containerID": "c", "state": map[string]any{"running": map[string]any{}}}}}})
	b.PutResource(pod)
	if findings, gaps, err = i.DiscoverIncidents(context.Background(), scope); err != nil || len(findings) != 0 || len(gaps) != 0 {
		t.Fatalf("healthy namespace reported unhealthy: %+v %v %v", findings, gaps, err)
	}
}

func TestDiscoverySkipsOperatorInfrastructureAndScaledDownWorkloads(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	operator := testkit.Resource("v1", "Pod", "demo", "agent-investigator", "operator-pod", map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "app:1"}}}, "status": map[string]any{"phase": "Pending"}})
	operator.SetLabels(map[string]string{api.OperatorLabel: api.OperatorLabelValue})
	b.PutResource(operator)
	b.PutResource(testkit.Resource("apps/v1", "Deployment", "demo", "paused", "paused-uid", map[string]any{"spec": map[string]any{"replicas": int64(0)}, "status": map[string]any{}}))
	findings, gaps, err := i.DiscoverIncidents(context.Background(), api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}, {APIVersion: "apps/v1", Kind: "Deployment"}}})
	if err != nil || len(findings) != 0 {
		t.Fatalf("operator or scaled-down workload reported: %+v %v", findings, err)
	}
	if len(gaps) != 0 {
		t.Fatalf("scaled-down Deployment reported as a gap: %v", gaps)
	}
}

func TestDiscoveryCoversReferenceKindsAndCronJobs(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	b.PutResource(testkit.Resource("networking.k8s.io/v1", "Ingress", "demo", "site", "ing-uid", map[string]any{"spec": map[string]any{"rules": []any{map[string]any{"http": map[string]any{"paths": []any{
		map[string]any{"path": "/", "backend": map[string]any{"service": map[string]any{"name": "missing", "port": map[string]any{"number": int64(80)}}}},
	}}}}}}))
	template := map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "run", "image": "busybox", "command": []any{"exit 1"}}}}}
	b.PutResource(testkit.Resource("batch/v1", "CronJob", "demo", "report", "cron-uid", map[string]any{"spec": map[string]any{"schedule": "0 * * * *", "jobTemplate": map[string]any{"spec": map[string]any{"template": template}}}}))
	controller := true
	for n, failed := range []bool{true, false} {
		condition := map[string]any{"type": "Complete", "status": "True"}
		if failed {
			condition = map[string]any{"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded"}
		}
		j := testkit.Resource("batch/v1", "Job", "demo", fmt.Sprintf("report-%d", n), fmt.Sprintf("job-%d", n), map[string]any{"spec": map[string]any{"template": template}, "status": map[string]any{"conditions": []any{condition}}})
		j.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "CronJob", Name: "report", UID: "cron-uid", Controller: &controller}})
		j.SetCreationTimestamp(testkit.Timestamp(time.Now().Add(time.Duration(n-2) * time.Hour)))
		b.PutResource(j)
	}
	scope := api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "networking.k8s.io/v1", Kind: "Ingress"}, {APIVersion: "batch/v1", Kind: "Job"}, {APIVersion: "batch/v1", Kind: "CronJob"}}}
	findings, _, err := i.DiscoverIncidents(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Target.Kind != "Ingress" {
		t.Fatalf("expected only the broken Ingress (the CronJob's latest run succeeded): %+v", findings)
	}
	// The latest run now fails: the failure belongs to the CronJob, once.
	b.Resources["demo/report-1"].Object["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded"}}}
	findings, _, err = i.DiscoverIncidents(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	kinds := []string{}
	for _, f := range findings {
		kinds = append(kinds, f.Target.Kind+"/"+f.Target.Name)
	}
	if len(findings) != 2 || !slices.Contains(kinds, "CronJob/report") || !slices.Contains(kinds, "Ingress/site") {
		t.Fatalf("failing CronJob not attributed once to the CronJob: %v", kinds)
	}
}

func TestApplicationErrorsAreExperimentalAndScoped(t *testing.T) {
	i, b, _ := setup(t)
	i.Policy.Authorization = "RBAC"
	labels := map[string]any{"app": "client"}
	b.PutResource(testkit.Resource("apps/v1", "Deployment", "demo", "client", "client-uid", map[string]any{"spec": map[string]any{"replicas": int64(1), "selector": map[string]any{"matchLabels": labels}, "template": map[string]any{"metadata": map[string]any{"labels": labels}}}}))
	pod := testkit.Resource("v1", "Pod", "demo", "client-1", "pod-uid", map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "busybox"}}}})
	pod.SetLabels(map[string]string{"app": "client"})
	b.PutResource(pod)
	b.RecentLog = map[string]string{"client-1/app": strings.Repeat("wget: can't connect to remote host (10.43.0.9): Connection refused\n", 5)}
	scope := api.Scope{Namespaces: []string{"demo"}}
	if found, _ := i.applicationErrors(context.Background(), scope, nil); len(found) != 0 {
		t.Fatal("application errors scanned without the experimental flag")
	}
	i.Policy.Experimental.ApplicationErrors = true
	found, _ := i.applicationErrors(context.Background(), scope, nil)
	if len(found) != 1 || found[0].Target.Name != "client" || found[0].Checks[0].Type != "LogSignature" || found[0].Checks[0].Query != "connection-refused" {
		t.Fatalf("application error not found: %+v", found)
	}
	if found, _ := i.applicationErrors(context.Background(), scope, found); len(found) != 0 {
		t.Fatal("workload already failing by status scanned again")
	}
}
