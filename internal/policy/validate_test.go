package policy

import (
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"testing"
)

func fixture() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "settings", "namespace": "demo", "uid": "cm-uid"}, "data": map[string]any{"mode": "broken"}}}
}
func allowed() Config {
	return Config{Capabilities: []Capability{{APIVersion: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespace: "demo", Names: []string{"settings"}, Types: []string{"PatchResource"}, Paths: map[string]ValueRule{"/data/mode": {Values: []any{"healthy"}}}, Risk: "low", RequireApproval: true}}}
}
func repair() api.Action {
	return api.Action{ID: "fix", Type: "PatchResource", Target: api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "settings", UID: "cm-uid"}, Patch: []api.PatchOp{{Op: "replace", Path: "/data/mode", Value: "healthy"}}}
}

func TestEmptyCapabilitiesDenyAll(t *testing.T) {
	if AuthorizeAction(repair(), fixture(), Config{}) == nil {
		t.Fatal("empty capabilities authorized write")
	}
}
func TestNamespaceAndNameCannotEscape(t *testing.T) {
	for _, mutate := range []func(*api.Action){func(a *api.Action) { a.Target.Namespace = "other" }, func(a *api.Action) { a.Target.Name = "other" }, func(a *api.Action) { a.Target.UID = "replacement" }, func(a *api.Action) { a.Type = "DeleteResource" }} {
		a := repair()
		mutate(&a)
		if AuthorizeAction(a, fixture(), allowed()) == nil {
			t.Fatal("scope escaped")
		}
	}
}
func TestJSONPointerEscapeCannotBypassAllowlist(t *testing.T) {
	for _, path := range []string{"/data/mode/child", "/data/~2mode", "/data", "/metadata/namespace", "/data/mo~1de", ""} {
		a := repair()
		a.Patch[0].Path = path
		if AuthorizeAction(a, fixture(), allowed()) == nil {
			t.Fatalf("path accepted %q", path)
		}
	}
}
func TestSecurityMetadataIsPreserved(t *testing.T) {
	a := repair()
	a.Patch = []api.PatchOp{{Op: "replace", Path: "/metadata/namespace", Value: "other"}}
	c := allowed()
	c.Capabilities[0].Paths["/metadata/namespace"] = ValueRule{Values: []any{"other"}}
	if AuthorizeAction(a, fixture(), c) == nil {
		t.Fatal("protected metadata accepted")
	}
	a = repair()
	a.Patch[0].Value = "arbitrary"
	if AuthorizeAction(a, fixture(), allowed()) == nil {
		t.Fatal("value rule ignored")
	}
	result, e := BuildResult(repair(), fixture())
	if e != nil {
		t.Fatal(e)
	}
	v, _, _ := unstructured.NestedString(result.Object, "data", "mode")
	if v != "healthy" || result.GetUID() != fixture().GetUID() {
		t.Fatal("repair or identity incorrect")
	}
}
func TestHighRiskCannotAutoExecute(t *testing.T) {
	p := api.PlanSpec{TargetRef: repair().Target, Actions: []api.Action{repair()}, PolicyDigest: PolicyDigest(allowed()), Verification: api.Verification{Type: "FieldEquals", TimeoutSeconds: 300, StableWindowSeconds: 120, Path: "/data/mode", Expected: "healthy"}}
	if ValidatePlan(api.TaskSpec{Mode: "Automatic", TargetRef: repair().Target}, p, allowed()) == nil {
		t.Fatal("automatic high impact accepted")
	}
	if e := ValidatePlan(api.TaskSpec{Mode: "HumanApproved", TargetRef: repair().Target}, p, allowed()); e != nil {
		t.Fatal(e)
	}
}
func TestDangerousResourcesRejected(t *testing.T) {
	for _, kind := range []string{"Secret", "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"} {
		a := repair()
		a.Target.Kind = kind
		c := allowed()
		c.Capabilities[0].Kind = kind
		u := fixture()
		u.SetKind(kind)
		if AuthorizeAction(a, u, c) == nil {
			t.Fatalf("dangerous resource %s authorized", kind)
		}
	}
}
