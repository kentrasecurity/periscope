package executor

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/testkit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"testing"
)

func TestPodRestartsChangeStableFingerprint(t *testing.T) {
	b := testkit.NewMemory()
	d := testkit.Resource("apps/v1", "Deployment", "demo", "api", "d", map[string]any{"spec": map[string]any{"replicas": int64(1), "selector": map[string]any{"matchLabels": map[string]any{"app": "api"}}}})
	p := healthyStandalonePod()
	p.SetName("api-pod")
	p.SetLabels(map[string]string{"app": "api"})
	linkPods(b, d, p)
	b.PutResource(p)
	ok, first, e := CheckPods(context.Background(), b, d)
	if !ok || e != nil {
		t.Fatalf("healthy pod rejected: %v", e)
	}
	p.Object["status"].(map[string]any)["containerStatuses"].([]any)[0].(map[string]any)["restartCount"] = int64(1)
	ok, second, e := CheckPods(context.Background(), b, d)
	if !ok || e != nil || first == second {
		t.Fatal("restart did not invalidate stable fingerprint")
	}
	delete(b.Resources, "demo/api-pod")
	ok, _, _ = CheckPods(context.Background(), b, d)
	if ok {
		t.Fatal("missing pods marked healthy")
	}
}

func linkPods(b *testkit.Memory, d, p *unstructured.Unstructured) {
	controller := true
	rs := testkit.Resource("apps/v1", "ReplicaSet", "demo", "api-rs", "rs", nil)
	rs.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: d.GetName(), UID: d.GetUID(), Controller: &controller}})
	p.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.GetName(), UID: types.UID("rs"), Controller: &controller}})
	b.PutResource(rs)
}
func TestDeploymentRecoveryRequiresCompleteDeclaredPodContainers(t *testing.T) {
	b := testkit.NewMemory()
	d := testkit.Resource("apps/v1", "Deployment", "demo", "api", "d", map[string]any{"spec": map[string]any{"replicas": int64(1), "selector": map[string]any{"matchLabels": map[string]any{"app": "api"}}}})
	pod := healthyStandalonePod()
	pod.SetLabels(map[string]string{"app": "api"})
	pod.Object["spec"].(map[string]any)["containers"] = append(pod.Object["spec"].(map[string]any)["containers"].([]any), map[string]any{"name": "missing", "image": "working"})
	linkPods(b, d, pod)
	b.PutResource(pod)
	if healthy, _, _ := CheckPods(context.Background(), b, d); healthy {
		t.Fatal("missing declared container accepted under DeploymentRecovery")
	}
}
