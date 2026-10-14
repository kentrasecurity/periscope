package admission

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"testing"
	"time"
)

var _ ReadBackend = (*kube.Client)(nil)

func requestSetup(t *testing.T) (*Validator, *testkit.Memory, admissionv1.AdmissionReview) {
	t.Helper()
	ctx := context.Background()
	b := testkit.NewMemory()
	u := testkit.Resource("v1", "ConfigMap", "demo", "settings", "target-uid", map[string]any{"data": map[string]any{"mode": "broken"}})
	b.PutResource(u)
	ref := api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "settings", UID: "target-uid"}
	task := b.PutTask("demo", "fix", "task-uid", api.TaskSpec{TargetRef: ref, Mode: "HumanApproved", Objective: "fix", Limits: api.DefaultLimits()})
	c := policy.Config{Namespaces: []string{"demo"}, Capabilities: []policy.Capability{{APIVersion: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespace: "demo", Names: []string{"settings"}, Types: []string{"PatchResource"}, Paths: map[string]policy.ValueRule{"/data/mode": {Values: []any{"healthy"}}}, RequireApproval: true, Risk: "low"}}}
	baseline, _ := api.DigestTarget(u)
	spec := api.PlanSpec{TaskRef: api.ObjectRef{Name: "fix", UID: "task-uid"}, TaskGeneration: 1, TargetRef: ref, Preconditions: api.Preconditions{SpecDigest: baseline}, PolicyDigest: policy.PolicyDigest(c), Diagnosis: "wrong mode", Risk: "low", Actions: []api.Action{{ID: "repair", Type: "PatchResource", Target: ref, Patch: []api.PatchOp{{Op: "replace", Path: "/data/mode", Value: "healthy"}}}}, Verification: api.Verification{Type: "FieldEquals", Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 300, StableWindowSeconds: 120}}
	spec.Digest, _ = api.DigestPlan(spec)
	p, _ := b.CreatePlan(ctx, "demo", "plan", spec)
	task.Status = api.TaskStatus{Phase: "Executing", ObservedGeneration: 1, PlanRef: &api.ObjectRef{Name: "plan", UID: string(p.Object.GetUID())}}
	now := time.Now().UTC()
	a := &kube.Approval{Object: testkit.Resource(api.Group+"/"+api.Version, "ActionApproval", "demo", "approve", "a", nil), Spec: api.ApprovalSpec{TaskUID: "task-uid", PlanUID: string(p.Object.GetUID()), PlanDigest: spec.Digest, ExpiresAt: now.Add(15 * time.Minute)}}
	a.Object.SetCreationTimestamp(testkit.Timestamp(now))
	b.ApprovalItems["demo/approve"] = a
	desired, _ := executor.PrepareResult(p, spec.Actions[0], u)
	after, _ := api.DigestTarget(desired)
	p.Status = api.PlanStatus{ApprovalUID: "a", Phase: "Executing", Entries: []api.JournalEntry{{ID: "repair", State: "Pending", Operation: executor.Operation(p, "repair"), BeforeDigest: baseline, AfterDigest: after, UpdatedAt: now}}}
	b.Claims[api.ClaimKey(p.Spec.TargetRef)] = string(p.Object.GetUID())
	old, _ := json.Marshal(u.Object)
	next, _ := json.Marshal(desired.Object)
	return &Validator{Backend: b, Policy: c, InvestigatorUser: "system:serviceaccount:demo:investigator", ExecutorUser: "system:serviceaccount:demo:executor"}, b, admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{UID: "review", Namespace: "demo", Name: "settings", Kind: metav1.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}, Resource: metav1.GroupVersionResource{Version: "v1", Resource: "configmaps"}, Operation: admissionv1.Update, UserInfo: authv1.UserInfo{Username: "system:serviceaccount:demo:executor"}, Object: runtime.RawExtension{Raw: next}, OldObject: runtime.RawExtension{Raw: old}}}
}
func TestDirectExecutorPatchRequiresApprovedPlan(t *testing.T) {
	v, b, r := requestSetup(t)
	if got := v.Validate(context.Background(), r); !got.Allowed {
		t.Fatalf("approved request denied: %v", got.Result)
	}
	b.ApprovalItems = map[string]*kube.Approval{}
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("direct executor bypassed approval")
	}
}
func TestForbiddenFieldPatchRejected(t *testing.T) {
	v, _, r := requestSetup(t)
	var object map[string]any
	_ = json.Unmarshal(r.Request.Object.Raw, &object)
	meta := object["metadata"].(map[string]any)
	meta["labels"] = map[string]any{"unapproved": "yes"}
	r.Request.Object.Raw, _ = json.Marshal(object)
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("unapproved result admitted")
	}
}
func TestMutatingWebhookChangedResultRejected(t *testing.T) {
	v, _, r := requestSetup(t)
	var object map[string]any
	_ = json.Unmarshal(r.Request.Object.Raw, &object)
	object["data"].(map[string]any)["side-effect"] = "injected"
	r.Request.Object.Raw, _ = json.Marshal(object)
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("mutated result admitted")
	}
}
func TestPlanAndApprovalImmutability(t *testing.T) {
	v, _, r := requestSetup(t)
	for _, kind := range []string{"ActionPlan", "ActionApproval"} {
		r.Request.Kind = metav1.GroupVersionKind{Group: api.Group, Version: api.Version, Kind: kind}
		r.Request.Resource.Group = api.Group
		r.Request.Object.Raw = []byte(`{"spec":{"digest":"changed"}}`)
		r.Request.OldObject.Raw = []byte(`{"spec":{"digest":"original"}}`)
		if v.Validate(context.Background(), r).Allowed {
			t.Fatalf("%s mutable", kind)
		}
	}
}
func TestAdmissionScopeDoesNotAffectUnrelatedUsers(t *testing.T) {
	v, _, r := requestSetup(t)
	r.Request.UserInfo.Username = "ordinary-administrator"
	if !v.Validate(context.Background(), r).Allowed {
		t.Fatal("unrelated workflow blocked")
	}
}
func TestAdmissionFailureClosed(t *testing.T) {
	v, _, r := requestSetup(t)
	r.Request.Object.Raw = []byte(`{`)
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("invalid review admitted")
	}
}
