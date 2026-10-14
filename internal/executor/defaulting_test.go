package executor

import (
	"context"
	"testing"
	"time"

	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type defaultingBackend struct {
	*testkit.Memory
	changeImage bool
}

func (b defaultingBackend) Execute(ctx context.Context, a api.Action, before, desired *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	if a.Type == "CreateResource" {
		desired = desired.DeepCopy()
		_ = unstructured.SetNestedField(desired.Object, "Always", "spec", "restartPolicy")
		_ = unstructured.SetNestedField(desired.Object, "ClusterFirst", "spec", "dnsPolicy")
		_ = unstructured.SetNestedField(desired.Object, int64(30), "spec", "terminationGracePeriodSeconds")
		_ = unstructured.SetNestedField(desired.Object, "default-scheduler", "spec", "schedulerName")
		containers, _, _ := unstructured.NestedSlice(desired.Object, "spec", "containers")
		containers[0].(map[string]any)["terminationMessagePolicy"] = "File"
		if b.changeImage {
			containers[0].(map[string]any)["image"] = "unapproved"
		}
		_ = unstructured.SetNestedSlice(desired.Object, containers, "spec", "containers")
	}
	return b.Memory.Execute(ctx, a, before, desired, dry)
}

// Whole-object digest comparison fails the valid case after normal API defaults.
// Ignoring explicitly proposed fields would incorrectly pass the changed case.
func TestPodCreationDefaultingPreservesExplicitManifest(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "defaults", true: "changed-image"}[changed], func(t *testing.T) {
			e, b, p, now := execution(t)
			e.Policy = policy.Config{Authorization: "RBAC", Namespaces: []string{"demo"}}
			e.Backend = defaultingBackend{b, changed}
			delete(b.Resources, "demo/settings")
			p.Spec.TargetRef = api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "settings"}
			p.Spec.Preconditions.SpecDigest = "absent"
			blueprint := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "settings", "namespace": "demo"}, "spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "known", "imagePullPolicy": "Never"}}, "securityContext": map[string]any{"runAsNonRoot": true}}}
			p.Spec.Actions = []api.Action{{ID: "create", Type: "CreateResource", Target: p.Spec.TargetRef, Object: blueprint}}
			p.Spec.Verification = api.Verification{Type: "ResourceExists", TimeoutSeconds: 300, StableWindowSeconds: 1}
			p.Spec.PolicyDigest = policy.PolicyDigest(e.Policy)
			p.Spec.Digest, _ = api.DigestPlan(p.Spec)
			b.Tasks["demo/fix"].Spec.TargetRef = p.Spec.TargetRef
			b.ApprovalItems["demo/approve"].Spec.PlanDigest = p.Spec.Digest
			for range 3 {
				if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
					t.Fatal(err)
				}
				*now = now.Add(2 * time.Second)
			}
			if changed {
				if b.Mutations != 0 || p.Status.Phase != "Failed" {
					t.Fatalf("unapproved image accepted: %d %s", b.Mutations, p.Status.Phase)
				}
				return
			}
			if b.Mutations != 1 || p.Status.Phase != "Succeeded" {
				t.Fatalf("normal defaults rejected: %d %s %+v", b.Mutations, p.Status.Phase, p.Status.Conditions)
			}
		})
	}
}

func TestCreatedPodFreezesDefaultsButAllowsSchedulerAssignment(t *testing.T) {
	for _, edit := range []bool{false, true} {
		t.Run(map[bool]string{false: "scheduled", true: "owner-edit"}[edit], func(t *testing.T) {
			e, b, p, now := execution(t)
			e.Policy = policy.Config{Authorization: "RBAC", Namespaces: []string{"demo"}}
			e.Backend = defaultingBackend{b, false}
			delete(b.Resources, "demo/settings")
			p.Spec.TargetRef = api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "settings"}
			p.Spec.Preconditions.SpecDigest = "absent"
			p.Spec.Actions = []api.Action{{ID: "create", Type: "CreateResource", Target: p.Spec.TargetRef, Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "settings", "namespace": "demo"}, "spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "known"}}}}}}
			p.Spec.Verification = api.Verification{Type: "ResourceExists", TimeoutSeconds: 300, StableWindowSeconds: 1}
			p.Spec.PolicyDigest = policy.PolicyDigest(e.Policy)
			p.Spec.Digest, _ = api.DigestPlan(p.Spec)
			b.Tasks["demo/fix"].Spec.TargetRef = p.Spec.TargetRef
			b.ApprovalItems["demo/approve"].Spec.PlanDigest = p.Spec.Digest
			if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
				t.Fatal(err)
			}
			if b.Mutations != 1 || p.Status.Phase != "Verifying" {
				t.Fatalf("create did not start verification: %d %s", b.Mutations, p.Status.Phase)
			}
			pod := b.Resources["demo/settings"]
			_ = unstructured.SetNestedField(pod.Object, "worker", "spec", "nodeName")
			if edit {
				pod.SetLabels(map[string]string{"unapproved": "edit"})
			}
			b.PutResource(pod)
			*now = now.Add(2 * time.Second)
			if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
				t.Fatal(err)
			}
			if edit && p.Status.Phase != "Failed" {
				t.Fatal("omitted-field owner edit bypassed frozen result")
			}
			if !edit && p.Status.Phase != "Succeeded" {
				t.Fatalf("scheduler assignment broke creation: %s %+v", p.Status.Phase, p.Status.Conditions)
			}
			if b.Mutations != 1 {
				t.Fatal("creation replayed")
			}
		})
	}
}
