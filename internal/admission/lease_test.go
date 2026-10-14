package admission

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestExecutorMayMaintainOnlyItsPlanClaim(t *testing.T) {
	v, b, r := requestSetup(t)
	p := b.Plans["demo/plan"]
	r.Request.Name = kube.ClaimName(api.ClaimKey(p.Spec.TargetRef))
	r.Request.Kind = metav1.GroupVersionKind{Group: "coordination.k8s.io", Version: "v1", Kind: "Lease"}
	r.Request.Resource = metav1.GroupVersionResource{Group: "coordination.k8s.io", Version: "v1", Resource: "leases"}
	r.Request.Operation = admissionv1.Create
	r.Request.Object.Raw, _ = json.Marshal(map[string]any{"metadata": map[string]any{"name": r.Request.Name, "namespace": "demo"}, "spec": map[string]any{"holderIdentity": string(p.Object.GetUID()), "leaseDurationSeconds": 120}})
	r.Request.OldObject.Raw = nil
	if !v.Validate(context.Background(), r).Allowed {
		t.Fatal("valid plan claim blocked")
	}
	r.Request.Name = "unrelated-leader-election"
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("unrelated lease authority granted")
	}
}
