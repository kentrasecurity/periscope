package policy

import (
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"testing"
)

func TestTemplateMetadataCannotBypassSecurityGuard(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "api", "namespace": "demo", "uid": "u"}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]any{"sidecar.istio.io/inject": "true"}}, "spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "approved"}}}}}}}
	replacement := u.DeepCopy().Object["spec"].(map[string]any)
	replacement["template"].(map[string]any)["metadata"].(map[string]any)["annotations"].(map[string]any)["sidecar.istio.io/inject"] = "false"
	for _, patch := range []api.PatchOp{{Op: "replace", Path: "/spec/template/metadata/annotations/sidecar.istio.io~1inject", Value: "false"}, {Op: "replace", Path: "/spec", Value: replacement}} {
		t.Run(patch.Path, func(t *testing.T) {
			a := api.Action{ID: "unsafe", Type: "PatchResource", Target: api.TargetRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "demo", Name: "api", UID: "u"}, Patch: []api.PatchOp{patch}}
			c := Config{Capabilities: []Capability{{APIVersion: "apps/v1", Kind: "Deployment", Resource: "deployments", Namespace: "demo", Names: []string{"api"}, Types: []string{"PatchResource"}, Paths: map[string]ValueRule{patch.Path: {Values: []any{patch.Value}}}, RequireApproval: true}}}
			if AuthorizeAction(a, u, c) == nil {
				t.Fatal("security-affecting template metadata change accepted")
			}
		})
	}
}
