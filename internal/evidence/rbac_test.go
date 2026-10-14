package evidence

import (
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"strings"
	"testing"
)

func TestRBACEvidenceIncludesRepairContextButNoCredentialValues(t *testing.T) {
	u := testkit.Resource("apps/v1", "Deployment", "demo", "app", "uid", map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "bad", "env": []any{map[string]any{"name": "MODE", "value": "broken"}, map[string]any{"name": "API_TOKEN", "value": "never-export-canary"}}, "readinessProbe": map[string]any{"httpGet": map[string]any{"port": int64(8081)}}}}}}}})
	raw, _ := json.Marshal(Project(u, policy.Config{Authorization: "RBAC"}))
	s := string(raw)
	if strings.Contains(s, "never-export-canary") || !strings.Contains(s, "broken") || !strings.Contains(s, "8081") {
		t.Fatal("credential leaked or repair context absent")
	}
	secret := testkit.Resource("v1", "Secret", "demo", "key", "uid", map[string]any{"data": map[string]any{"key": "never-export-canary"}})
	raw, _ = json.Marshal(Project(secret, policy.Config{Authorization: "RBAC"}))
	if strings.Contains(string(raw), "never-export-canary") {
		t.Fatal("secret payload exposed")
	}
}

func TestRBACCredentialURLsAndProbeAuthorizationAreRedacted(t *testing.T) {
	value := map[string]any{"env": []any{map[string]any{"name": "DATABASE_URL", "value": "postgres://dbuser:db-credential-canary@database/app"}}, "readinessProbe": map[string]any{"httpGet": map[string]any{"httpHeaders": []any{map[string]any{"name": "Authorization", "value": "Basic probe-credential-canary"}}}}}
	raw, _ := json.Marshal(sanitize(value))
	for _, canary := range []string{"db-credential-canary", "probe-credential-canary"} {
		if strings.Contains(string(raw), canary) {
			t.Fatalf("credential exposed: %s", canary)
		}
	}
}

func TestRBACProjectionPreservesScopedPodLabelsWithoutCredentials(t *testing.T) {
	pod := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "probe", "namespace": "demo", "labels": map[string]any{"app": "probe-client", "api-key": "label-secret-canary"}}}}
	projected := projectRBAC(pod)
	metadata := projected["metadata"].(map[string]any)
	labels, ok := metadata["labels"].(map[string]any)
	if !ok || labels["app"] != "probe-client" {
		t.Fatal("scoped labels unavailable for NetworkPolicy diagnosis")
	}
	if labels["api-key"] != "[REDACTED]" {
		t.Fatal("sensitive label value escaped")
	}
}
