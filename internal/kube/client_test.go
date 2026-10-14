package kube

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	kt "k8s.io/client-go/testing"
	"testing"
)

func TestClientUsesNamespaceAndStatusSubresource(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.Group + "/" + api.Version, "kind": "AgentTask", "metadata": map[string]any{"name": "task", "namespace": "demo", "uid": "task-uid", "generation": int64(1)}, "spec": JSONMap(api.TaskSpec{TargetRef: api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Name: "settings"}, Mode: "HumanApproved", Objective: "fix", Limits: api.DefaultLimits()})}}
	d := fake.NewSimpleDynamicClient(runtime.NewScheme(), u)
	seen := false
	d.PrependReactor("update", "agenttasks", func(action kt.Action) (bool, runtime.Object, error) {
		if action.GetNamespace() != "demo" || action.GetSubresource() != "status" {
			t.Error("status authority escaped")
		}
		seen = true
		return false, nil, nil
	})
	c := &Client{Dynamic: d}
	task, e := c.GetTask(context.Background(), "demo", "task")
	if e != nil {
		t.Fatal(e)
	}
	task.Status.Phase = "Collecting"
	if e = c.SaveTaskStatus(context.Background(), task); e != nil || !seen {
		t.Fatalf("status write %v", e)
	}
}
func TestMappingRejectsClusterScopedTargets(t *testing.T) {
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Version: "v1"}})
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "Node"}, meta.RESTScopeRoot)
	c := &Client{Mapper: mapper}
	if _, e := c.Mapping(api.TargetRef{APIVersion: "v1", Kind: "Node", Namespace: "demo", Name: "node"}); e == nil {
		t.Fatal("cluster target used namespaced authority")
	}
}
