package executor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kentrasecurity/periscope/internal/testkit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func referenceFixture() *testkit.Memory {
	b := testkit.NewMemory()
	labels := map[string]any{"app": "web"}
	b.PutResource(testkit.Resource("apps/v1", "Deployment", "demo", "web-app", "web-uid", map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"labels": labels}, "spec": map[string]any{"containers": []any{
		map[string]any{"name": "web", "image": "nginx", "env": []any{map[string]any{"name": "MODE", "valueFrom": map[string]any{"configMapKeyRef": map[string]any{"name": "settings", "key": "mdoe", "optional": true}}}}},
	}}}}}))
	b.PutResource(testkit.Resource("v1", "Service", "demo", "web", "svc-uid", map[string]any{"spec": map[string]any{"selector": labels, "ports": []any{map[string]any{"name": "http", "port": int64(80)}}}}))
	return b
}

func references(t *testing.T, b *testkit.Memory, u *unstructured.Unstructured) (bool, string) {
	t.Helper()
	b.PutResource(u)
	healthy, _, observation, err := CheckReferences(context.Background(), b, u)
	if err != nil {
		t.Fatal(err)
	}
	return healthy, observation
}

func ingress(name string, port map[string]any) *unstructured.Unstructured {
	return testkit.Resource("networking.k8s.io/v1", "Ingress", "demo", "site", "ing-uid", map[string]any{"spec": map[string]any{"rules": []any{map[string]any{"http": map[string]any{"paths": []any{
		map[string]any{"path": "/", "backend": map[string]any{"service": map[string]any{"name": name, "port": port}}},
	}}}}}})
}

func TestIngressBackendReferences(t *testing.T) {
	b := referenceFixture()
	if healthy, observation := references(t, b, ingress("web", map[string]any{"number": int64(80)})); !healthy {
		t.Fatalf("working Ingress reported broken: %s", observation)
	}
	if healthy, observation := references(t, b, ingress("wbe", map[string]any{"number": int64(80)})); healthy || !strings.Contains(observation, `Service "wbe" does not exist (nearest Service: "web")`) {
		t.Fatalf("missing backend not reported: %s", observation)
	}
	if healthy, observation := references(t, b, ingress("web", map[string]any{"name": "https"})); healthy || !strings.Contains(observation, `port "https" is not exposed by Service "web"`) {
		t.Fatalf("wrong backend port not reported: %s", observation)
	}
}

func TestSelectorReferences(t *testing.T) {
	b := referenceFixture()
	pdb := testkit.Resource("policy/v1", "PodDisruptionBudget", "demo", "web", "pdb-uid", map[string]any{"spec": map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "wbe"}}}})
	if healthy, observation := references(t, b, pdb); healthy || !strings.Contains(observation, "selector app=wbe matches no Pod") {
		t.Fatalf("PDB selector typo not reported: %s", observation)
	}
	policy := testkit.Resource("networking.k8s.io/v1", "NetworkPolicy", "demo", "web", "np-uid", map[string]any{"spec": map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
		"ingress":     []any{map[string]any{"from": []any{map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app": "frontnd"}}}}}},
	}})
	if healthy, observation := references(t, b, policy); healthy || !strings.Contains(observation, "ingress[0].from[0].podSelector app=frontnd matches no Pod") {
		t.Fatalf("NetworkPolicy peer typo not reported: %s", observation)
	}
	open := testkit.Resource("networking.k8s.io/v1", "NetworkPolicy", "demo", "all", "np2-uid", map[string]any{"spec": map[string]any{"podSelector": map[string]any{}}})
	if healthy, observation := references(t, b, open); !healthy {
		t.Fatalf("namespace-wide policy reported broken: %s", observation)
	}
}

func cronJob(b *testkit.Memory, command string) *unstructured.Unstructured {
	c := testkit.Resource("batch/v1", "CronJob", "demo", "report", "cron-uid", map[string]any{"spec": map[string]any{"schedule": "0 * * * *", "jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "run", "image": "busybox", "command": []any{command}}}}}}}}})
	b.PutResource(c)
	return c
}

func job(b *testkit.Memory, name, command string, age time.Duration, failed bool) {
	condition := map[string]any{"type": "Complete", "status": "True"}
	if failed {
		condition = map[string]any{"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded", "message": "Job has reached the specified backoff limit"}
	}
	j := testkit.Resource("batch/v1", "Job", "demo", name, name+"-uid", map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "run", "image": "busybox", "command": []any{command}}}}}}, "status": map[string]any{"conditions": []any{condition}}})
	controller := true
	j.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "CronJob", Name: "report", UID: "cron-uid", Controller: &controller}})
	j.SetCreationTimestamp(testkit.Timestamp(time.Now().Add(-age)))
	b.PutResource(j)
}

func TestCronJobJudgedByLatestRunOfCurrentTemplate(t *testing.T) {
	b := referenceFixture()
	c := cronJob(b, "brokn")
	job(b, "report-1", "brokn", time.Hour, false)
	job(b, "report-2", "brokn", time.Minute, true)
	if healthy, observation := references(t, b, c); healthy || !strings.Contains(observation, "most recent Job report-2 failed (BackoffLimitExceeded") {
		t.Fatalf("failing CronJob not reported: %s", observation)
	}
	c = cronJob(b, "fixed")
	if healthy, observation := references(t, b, c); !healthy {
		t.Fatalf("failure of the replaced template held against the CronJob: %s", observation)
	}
	job(b, "report-3", "fixed", time.Second, false)
	c = cronJob(b, "brokn") // the latest run succeeded; older failures are history
	if healthy, observation := references(t, b, c); !healthy {
		t.Fatalf("CronJob judged by an older run: %s", observation)
	}
}

func TestOptionalConfigMapKeyTypo(t *testing.T) {
	b := referenceFixture()
	settings := testkit.Resource("v1", "ConfigMap", "demo", "settings", "cm-uid", map[string]any{"data": map[string]any{"mode": "fast"}})
	if healthy, observation := references(t, b, settings); healthy || !strings.Contains(observation, `Deployment/web-app references optional key "mdoe" of ConfigMap settings, which does not exist (nearest key: "mode")`) {
		t.Fatalf("silent optional key typo not reported: %s", observation)
	}
	unrelated := testkit.Resource("v1", "ConfigMap", "demo", "settings", "cm-uid", map[string]any{"data": map[string]any{"level": "debug"}})
	if healthy, observation := references(t, b, unrelated); !healthy {
		t.Fatalf("intentionally absent optional key reported: %s", observation)
	}
}
