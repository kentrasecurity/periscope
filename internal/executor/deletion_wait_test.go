package executor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type createDenied struct{ *testkit.Memory }

func (b createDenied) Authorize(_ context.Context, a api.Action) error {
	if a.Type == "CreateResource" {
		return fmt.Errorf("create forbidden by owner RBAC")
	}
	return nil
}

func TestReplacementChecksCreatePermissionBeforeDeleting(t *testing.T) {
	e, b, p, _ := execution(t)
	e.Policy = policy.Config{CoordinationNamespace: "demo", Authorization: "RBAC", Namespaces: []string{"demo"}}
	e.Backend = createDenied{b}
	ref := p.Spec.TargetRef
	next := ref
	next.UID = ""
	p.Spec.Targets = []api.TargetBinding{{ID: "old", Target: ref, Preconditions: p.Spec.Preconditions}, {ID: "new", Target: next, Preconditions: api.Preconditions{SpecDigest: "absent"}, AfterActionID: "delete"}}
	p.Spec.Actions = []api.Action{{ID: "delete", BindingID: "old", Type: "DeleteResource", Target: ref}, {ID: "create", BindingID: "new", Type: "CreateResource", Target: next, Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": ref.Name, "namespace": ref.Namespace}, "data": map[string]any{"mode": "healthy"}}}}
	p.Spec.PolicyDigest = policy.PolicyDigest(e.Policy)
	p.Spec.Digest, _ = api.DigestPlan(p.Spec)
	b.ApprovalItems["demo/approve"].Spec.PlanDigest = p.Spec.Digest
	if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if b.Mutations != 0 || b.Resources["demo/settings"] == nil || p.Status.Phase != "Failed" {
		t.Fatalf("deleted without create permission: mutations=%d phase=%s", b.Mutations, p.Status.Phase)
	}
}

type delayedDelete struct{ *testkit.Memory }

func (b delayedDelete) Execute(ctx context.Context, a api.Action, before, desired *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	if a.Type == "DeleteResource" && !dry {
		b.Mutations++
		u := before.DeepCopy()
		stamp := metav1.Now()
		u.SetDeletionTimestamp(&stamp)
		b.PutResource(u)
		return nil, nil
	}
	return b.Memory.Execute(ctx, a, before, desired, dry)
}

// Treating DELETE acknowledgement as absence must not authorize an early CREATE.
func TestReplacementWaitsForConfirmedDeletion(t *testing.T) {
	e, b, p, now := execution(t)
	e.Policy = policy.Config{CoordinationNamespace: "demo", Authorization: "RBAC", Namespaces: []string{"demo"}}
	e.Backend = delayedDelete{b}
	ref := p.Spec.TargetRef
	createRef := ref
	createRef.UID = ""
	p.Spec.Targets = []api.TargetBinding{{ID: "old", Target: ref, Preconditions: p.Spec.Preconditions}, {ID: "new", Target: createRef, Preconditions: api.Preconditions{SpecDigest: "absent"}, AfterActionID: "delete"}}
	p.Spec.Actions = []api.Action{{ID: "delete", BindingID: "old", Type: "DeleteResource", Target: ref}, {ID: "create", BindingID: "new", Type: "CreateResource", Target: createRef, Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": ref.Name, "namespace": ref.Namespace}, "data": map[string]any{"mode": "healthy"}}}}
	p.Spec.PolicyDigest = policy.PolicyDigest(e.Policy)
	p.Spec.Digest, _ = api.DigestPlan(p.Spec)
	b.ApprovalItems["demo/approve"].Spec.PlanDigest = p.Spec.Digest
	for range 2 {
		if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(time.Second)
		if b.Mutations != 1 || p.Status.Phase != "Executing" {
			t.Fatalf("did not wait for deletion: mutations=%d phase=%s conditions=%+v", b.Mutations, p.Status.Phase, p.Status.Conditions)
		}
	}
	delete(b.Resources, "demo/settings")
	for range 3 {
		if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(2 * time.Second)
	}
	if b.Mutations != 2 || p.Status.Phase != "Succeeded" {
		t.Fatalf("replacement not resumed: %d %s %+v", b.Mutations, p.Status.Phase, p.Status.Conditions)
	}
}
