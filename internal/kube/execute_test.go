package kube

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	kt "k8s.io/client-go/testing"
	"testing"
)

func TestExecuteUsesConditionalPatch(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "settings", "namespace": "demo", "uid": "u", "resourceVersion": "3"}, "data": map[string]any{"mode": "broken"}}}
	d := fake.NewSimpleDynamicClient(runtime.NewScheme(), u)
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Version: "v1"}})
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}, meta.RESTScopeNamespace)
	c := &Client{Dynamic: d, Mapper: mapper}
	desired := u.DeepCopy()
	_ = unstructured.SetNestedField(desired.Object, "healthy", "data", "mode")
	seen := false
	d.PrependReactor("patch", "configmaps", func(action kt.Action) (bool, runtime.Object, error) {
		p := action.(kt.PatchAction)
		var ops []api.PatchOp
		if e := json.Unmarshal(p.GetPatch(), &ops); e != nil {
			t.Fatal(e)
		}
		if len(ops) < 3 || ops[0].Op != "test" || ops[0].Path != "/metadata/resourceVersion" || ops[0].Value != "3" || ops[1].Path != "/metadata/uid" {
			t.Error("conditional fencing missing")
		}
		seen = true
		return false, nil, nil
	})
	_, e := c.Execute(context.Background(), api.Action{Type: "PatchResource", Target: api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Name: "settings", Namespace: "demo", UID: "u"}}, u, desired, false)
	if e != nil || !seen {
		t.Fatalf("conditional patch %v", e)
	}
}
