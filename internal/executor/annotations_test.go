package executor

import (
	"testing"

	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/testkit"
)

func TestAppliedWriteSurvivesForeignAnnotations(t *testing.T) {
	ingress := testkit.Resource("networking.k8s.io/v1", "Ingress", "demo", "site", "uid", map[string]any{"spec": map[string]any{"rules": []any{}}})
	ingress.SetAnnotations(map[string]string{"nginx.ingress.kubernetes.io/rewrite-target": "/", api.OperationAnnotation: "op"})
	a := api.Action{ID: "fix", Type: "PatchResource", Target: api.TargetRef{APIVersion: "networking.k8s.io/v1", Kind: "Ingress", Namespace: "demo", Name: "site", UID: "uid"}, Patch: []api.PatchOp{{Op: "replace", Path: "/spec/rules", Value: []any{}}}}
	applied, _ := ResultDigest(ingress, a)
	observed := ingress.DeepCopy()
	annotations := observed.GetAnnotations()
	annotations["field.cattle.io/publicEndpoints"] = `[{"port":80}]` // added by Rancher after the write
	observed.SetAnnotations(annotations)
	if digest, _ := ResultDigest(observed, a); digest != applied {
		t.Fatal("a controller's annotation made the applied write look unapplied")
	}
	if SameAnnotations(ingress, observed) {
		t.Fatal("a write adding annotations would pass admission")
	}
	changed := observed.DeepCopy()
	changed.Object["spec"] = map[string]any{"rules": []any{map[string]any{"host": "other"}}}
	if digest, _ := ResultDigest(changed, a); digest == applied {
		t.Fatal("a later spec change is not detected")
	}
	annotate := a
	annotate.Patch = []api.PatchOp{{Op: "add", Path: "/metadata/annotations/nginx.ingress.kubernetes.io~1rewrite-target", Value: "/v2"}}
	rewritten := ingress.DeepCopy()
	rewritten.SetAnnotations(map[string]string{"nginx.ingress.kubernetes.io/rewrite-target": "/v3", api.OperationAnnotation: "op"})
	if x, _ := ResultDigest(ingress, annotate); x == func() string { d, _ := ResultDigest(rewritten, annotate); return d }() {
		t.Fatal("a patched annotation is not covered by the digest")
	}
}
