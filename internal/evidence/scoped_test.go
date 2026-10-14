package evidence

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"strings"
	"testing"
)

type trackedReads struct {
	*testkit.Memory
	names []string
}

func (r *trackedReads) Get(ctx context.Context, t api.TargetRef) (*unstructured.Unstructured, error) {
	r.names = append(r.names, t.Name)
	return r.Memory.Get(ctx, t)
}
func TestScopedSeedEvidenceExcludesOwnerReadsAndContents(t *testing.T) {
	reader := &trackedReads{Memory: testkit.NewMemory()}
	owner := testkit.Resource("apps/v1", "Deployment", "demo", "excluded", "owner", map[string]any{"spec": map[string]any{"sensitiveEvidence": "do-not-export"}})
	reader.PutResource(owner)
	pod := testkit.Resource("v1", "Pod", "demo", "app", "pod", nil)
	controller := true
	pod.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "excluded", UID: owner.GetUID(), Controller: &controller}})
	reader.PutResource(pod)
	collector := Collector{Reader: reader, Policy: policy.Config{Authorization: "RBAC", Namespaces: []string{"demo"}}, MaxToolCalls: 30, Scope: &api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod", Name: "app"}}}}
	bundle, err := collector.Collect(context.Background(), api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "app"}, "demo")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range reader.names {
		if name == "excluded" {
			t.Fatal("excluded owner read")
		}
	}
	for _, e := range bundle.Evidence {
		if strings.Contains(e.Content, "do-not-export") || strings.HasPrefix(e.Source, "owner:") {
			t.Fatal("excluded evidence exported")
		}
	}
}
