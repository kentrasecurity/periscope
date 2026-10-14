package policy

import (
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"testing"
)

func TestParentPatchCannotChangeProtectedDescendants(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "api", "namespace": "demo", "uid": "u"}, "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"serviceAccountName": "restricted", "containers": []any{map[string]any{"name": "api", "image": "approved"}}}}}}}
	value := map[string]any{"template": map[string]any{"spec": map[string]any{"serviceAccountName": "admin", "containers": []any{map[string]any{"name": "api", "image": "approved"}}}}}
	a := api.Action{ID: "fix", Type: "PatchResource", Target: api.TargetRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "demo", Name: "api", UID: "u"}, Patch: []api.PatchOp{{Op: "replace", Path: "/spec", Value: value}}}
	c := Config{Capabilities: []Capability{{APIVersion: "apps/v1", Kind: "Deployment", Resource: "deployments", Namespace: "demo", Names: []string{"api"}, Types: []string{"PatchResource"}, Paths: map[string]ValueRule{"/spec": {Values: []any{value}}}, RequireApproval: true}}}
	if AuthorizeAction(a, u, c) == nil {
		t.Fatal("parent replacement bypassed protected descendant check")
	}
}
