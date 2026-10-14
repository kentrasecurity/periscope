package executor

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"testing"
)

func TestStatefulSetStaleRevisionCannotSatisfyRecovery(t *testing.T) {
	u := testkit.Resource("apps/v1", "StatefulSet", "demo", "db", "uid", map[string]any{"spec": map[string]any{"replicas": int64(1)}, "status": map[string]any{"observedGeneration": int64(1), "readyReplicas": int64(1), "updatedReplicas": int64(0), "currentRevision": "old", "updateRevision": "new"}})
	if healthy, _, _ := CheckResourceHealth(u); healthy {
		t.Fatal("old ready revision satisfied desired recovery")
	}
}

type listOnly map[string][]*unstructured.Unstructured

func (l listOnly) List(_ context.Context, version, kind, _, _ string) ([]*unstructured.Unstructured, error) {
	return l[version+"/"+kind], nil
}

func TestServiceHealthNeedsAPossibleBackend(t *testing.T) {
	svc := testkit.Resource("v1", "Service", "demo", "web", "svc", map[string]any{"spec": map[string]any{"selector": map[string]any{"app": "web"}}})
	if healthy, _, err := CheckService(context.Background(), listOnly{}, svc); err != nil || healthy {
		t.Fatal("selector matching nothing reported healthy")
	}
	scaledDown := listOnly{"apps/v1/Deployment": {testkit.Resource("apps/v1", "Deployment", "demo", "web", "d", map[string]any{"spec": map[string]any{"replicas": int64(0), "template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "web"}}}}})}}
	if healthy, _, err := CheckService(context.Background(), scaledDown, svc); err != nil || !healthy {
		t.Fatal("intentionally scaled-down backend reported broken")
	}
	external := testkit.Resource("v1", "Service", "demo", "ext", "ext", map[string]any{"spec": map[string]any{"type": "ExternalName", "externalName": "example.com"}})
	if healthy, _, _ := CheckService(context.Background(), listOnly{}, external); !healthy {
		t.Fatal("ExternalName Service needs no selector backend")
	}
}

func TestClaimJobAndReplicaSetHealth(t *testing.T) {
	waiting := testkit.Resource("v1", "PersistentVolumeClaim", "demo", "data", "pvc", map[string]any{"status": map[string]any{"phase": "Pending"}})
	if healthy, _, _ := CheckResourceHealth(waiting); !healthy {
		t.Fatal("WaitForFirstConsumer claim reported broken")
	}
	waiting.SetAnnotations(map[string]string{"volume.kubernetes.io/selected-node": "node-1"})
	if healthy, _, _ := CheckResourceHealth(waiting); healthy {
		t.Fatal("claim failing to provision for a scheduled consumer reported healthy")
	}
	failed := testkit.Resource("batch/v1", "Job", "demo", "migrate", "job", map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded"}}}})
	if healthy, _, err := CheckResourceHealth(failed); err != nil || healthy {
		t.Fatal("failed Job reported healthy")
	}
	running := testkit.Resource("batch/v1", "Job", "demo", "run", "job2", map[string]any{"status": map[string]any{"active": int64(1)}})
	if healthy, _, err := CheckResourceHealth(running); err != nil || !healthy {
		t.Fatal("running Job reported broken")
	}
	quota := testkit.Resource("apps/v1", "ReplicaSet", "demo", "web-1", "rs", map[string]any{"spec": map[string]any{"replicas": int64(1)}, "status": map[string]any{"observedGeneration": int64(1), "conditions": []any{map[string]any{"type": "ReplicaFailure", "status": "True", "reason": "FailedCreate"}}}})
	if healthy, _, err := CheckResourceHealth(quota); err != nil || healthy {
		t.Fatal("ReplicaSet unable to create Pods reported healthy")
	}
}

func TestFailureSignatureIgnoresRestartCounters(t *testing.T) {
	pod := func(restarts int64, state map[string]any) *unstructured.Unstructured {
		return testkit.Resource("v1", "Pod", "demo", "app", "pod", map[string]any{"status": map[string]any{"phase": "Running", "conditions": []any{map[string]any{"type": "Ready", "status": "False"}}, "containerStatuses": []any{map[string]any{"name": "app", "restartCount": restarts, "state": state, "lastState": map[string]any{"terminated": map[string]any{"reason": "Error", "finishedAt": "t"}}}}}})
	}
	waiting := map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff"}}
	running := map[string]any{"running": map[string]any{"startedAt": "now"}}
	if FailureSignature(pod(3, waiting)) != FailureSignature(pod(7, running)) {
		t.Fatal("crash loop counters changed the incident identity")
	}
	pulled := pod(0, map[string]any{"waiting": map[string]any{"reason": "ImagePullBackOff"}})
	if FailureSignature(pulled) == FailureSignature(pod(3, waiting)) {
		t.Fatal("different failure reasons share an identity")
	}
}

func TestNearestBackendPrefersTypoTargetOverOtherApplications(t *testing.T) {
	b := testkit.NewMemory()
	for _, name := range []string{"suite-web", "suite-probe", "suite-image"} {
		b.PutResource(testkit.Resource("apps/v1", "Deployment", "demo", name, name+"-uid", map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app.kubernetes.io/name": name}}}}}))
	}
	service := testkit.Resource("v1", "Service", "demo", "svc", "svc-uid", map[string]any{"spec": map[string]any{"selector": map[string]any{"app.kubernetes.io/name": "suite-wbe"}}})
	if got := NearestBackend(context.Background(), b, service); got != "Deployment/suite-web (template labels app.kubernetes.io/name=suite-web)" {
		t.Fatalf("nearest backend %q", got)
	}
	service.Object["spec"] = map[string]any{"selector": map[string]any{"app.kubernetes.io/name": "billing"}}
	if got := NearestBackend(context.Background(), b, service); got != "" {
		t.Fatalf("unrelated selector matched %q", got)
	}
}
