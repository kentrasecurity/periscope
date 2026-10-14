package kube

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	"testing"
)

func TestCurrentApprovalLookupIgnoresNamespaceHistory(t *testing.T) {
	objects := []runtime.Object{}
	for n := 0; n < 1100; n++ {
		uid := "old"
		name := fmt.Sprintf("review-%d", n)
		if n == 1099 {
			uid = "current"
		}
		objects = append(objects, &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.Group + "/" + api.Version, "kind": "ActionApproval", "metadata": map[string]any{"name": name, "namespace": "demo", "labels": map[string]any{api.Group + "/plan-uid": uid}}, "spec": JSONMap(api.ApprovalSpec{PlanUID: uid})}})
	}
	client := &Client{Dynamic: fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{ApprovalGVR: "ActionApprovalList"}, objects...)}
	items, err := client.ApprovalsForPlan(context.Background(), "demo", "current")
	if err != nil || len(items) != 1 || items[0].Spec.PlanUID != "current" {
		t.Fatalf("history impeded current approvals: %d %v", len(items), err)
	}
}
