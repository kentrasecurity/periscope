package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/testkit"
)

func TestLogSignatureCheckFollowsRecentLogs(t *testing.T) {
	b := testkit.NewMemory()
	labels := map[string]any{"app": "client"}
	b.PutResource(testkit.Resource("apps/v1", "Deployment", "demo", "client", "client-uid", map[string]any{"spec": map[string]any{"selector": map[string]any{"matchLabels": labels}, "template": map[string]any{"metadata": map[string]any{"labels": labels}}}}))
	pod := testkit.Resource("v1", "Pod", "demo", "client-1", "pod-uid", map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "busybox"}}}})
	pod.SetLabels(map[string]string{"app": "client"})
	b.PutResource(pod)
	b.RecentLog = map[string]string{"client-1/app": strings.Repeat("ERROR: request to http://backend failed: wget: download timed out token=sk-proj-abcdefghijklmnopqrstuvwxyz\n", 4)}
	check := api.Check{ID: "application-errors", Type: "LogSignature", Target: api.TargetRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "demo", Name: "client"}, Query: "timeout", TimeoutSeconds: 600, StableWindowSeconds: 60}
	c := CheckEvaluator{Reader: b, Pods: b}
	results, err := c.EvaluateChecks(context.Background(), []api.Check{check})
	if err != nil || results[0].Healthy || !strings.Contains(results[0].Observation, `4 log line(s) in the last 180s match application error "timeout"`) || strings.Contains(results[0].Observation, "sk-proj") {
		t.Fatalf("recent application errors not reported (or not redacted): %+v %v", results, err)
	}
	b.RecentLog["client-1/app"] = "GET http://backend 200\n" // repaired: old errors aged out of the window
	results, _ = c.EvaluateChecks(context.Background(), []api.Check{check})
	if !results[0].Healthy {
		t.Fatalf("recovered workload still failing: %+v", results)
	}
}
