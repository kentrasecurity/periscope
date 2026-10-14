package executor

import (
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"testing"
)

func healthyStandalonePod() *unstructured.Unstructured {
	return testkit.Resource("v1", "Pod", "demo", "app", "pod-uid", map[string]any{
		"spec":   map[string]any{"containers": []any{map[string]any{"name": "app", "image": "working"}}},
		"status": map[string]any{"phase": "Running", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}, "containerStatuses": []any{map[string]any{"name": "app", "image": "working", "ready": true, "containerID": "container-1", "restartCount": int64(0), "state": map[string]any{"running": map[string]any{}}}}}})
}
func TestPodRecoveryRequiresCompleteHealthyStatus(t *testing.T) {
	p := healthyStandalonePod()
	ok, _, err := CheckResource(p, api.Verification{Type: "PodRecovery"})
	if err != nil || !ok {
		t.Fatalf("healthy Pod rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*unstructured.Unstructured)
	}{
		{"missing", func(p *unstructured.Unstructured) {
			p.Object["spec"].(map[string]any)["containers"] = append(p.Object["spec"].(map[string]any)["containers"].([]any), map[string]any{"name": "missing"})
		}},
		{"waiting", func(p *unstructured.Unstructured) {
			p.Object["status"].(map[string]any)["containerStatuses"].([]any)[0].(map[string]any)["state"] = map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff"}}
		}},
		{"init", func(p *unstructured.Unstructured) {
			p.Object["spec"].(map[string]any)["initContainers"] = []any{map[string]any{"name": "init"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := p.DeepCopy()
			tc.change(x)
			ok, _, _ := CheckResource(x, api.Verification{Type: "PodRecovery"})
			if ok {
				t.Fatal("unhealthy Pod accepted")
			}
		})
	}
}
func TestPodRecoveryFingerprintResetsOnRestartOrContainerReplacement(t *testing.T) {
	p := healthyStandalonePod()
	_, before, _ := CheckResource(p, api.Verification{Type: "PodRecovery"})
	p.Object["status"].(map[string]any)["containerStatuses"].([]any)[0].(map[string]any)["restartCount"] = int64(1)
	_, after, _ := CheckResource(p, api.Verification{Type: "PodRecovery"})
	if before == after {
		t.Fatal("restart did not alter stability fingerprint")
	}
}
func TestPodRecoveryRejectsStaleReadyImage(t *testing.T) {
	pod := healthyStandalonePod()
	pod.Object["status"].(map[string]any)["containerStatuses"].([]any)[0].(map[string]any)["image"] = "old-image"
	if healthy, _, _ := CheckPod(pod); healthy {
		t.Fatal("stale ready containers satisfy changed desired image")
	}
}
