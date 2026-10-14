package policy

import (
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"strings"
	"testing"
)

func TestRBACRepairsNeedNoFieldCatalog(t *testing.T) {
	c := Config{Authorization: "RBAC", Namespaces: []string{"demo"}}
	u := testkit.Resource("apps/v1", "Deployment", "demo", "api", "uid", map[string]any{"spec": map[string]any{"replicas": int64(1), "template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "bad"}}}}}})
	for _, op := range []api.PatchOp{{Op: "replace", Path: "/spec/template/spec/containers/0/image", Value: "good"}, {Op: "replace", Path: "/spec/replicas", Value: float64(2)}} {
		a := api.Action{ID: "repair", Type: "PatchResource", Target: api.TargetRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "demo", Name: "api", UID: "uid"}, Patch: []api.PatchOp{op}}
		if err := AuthorizeAction(a, u, c); err != nil {
			t.Fatal(err)
		}
	}
}
func TestRBACStillProtectsProtocolAndIdentity(t *testing.T) {
	c := Config{Authorization: "RBAC", Namespaces: []string{"demo"}}
	u := testkit.Resource("v1", "ConfigMap", "demo", "cfg", "uid", map[string]any{"data": map[string]any{"mode": "broken"}})
	a := api.Action{ID: "repair", Type: "PatchResource", Target: api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "cfg", UID: "uid"}, Patch: []api.PatchOp{{Op: "replace", Path: "/metadata/name", Value: "other"}}}
	if AuthorizeAction(a, u, c) == nil {
		t.Fatal("identity change allowed")
	}
	a.Target = api.TargetRef{APIVersion: api.Group + "/" + api.Version, Kind: "ActionApproval", Namespace: "demo", Name: "approval", UID: "uid"}
	if AuthorizeAction(a, nil, c) == nil {
		t.Fatal("approval protocol used as repair target")
	}
}
func TestPodRepairPlanUsesPodRecovery(t *testing.T) {
	c := Config{Authorization: "RBAC", Namespaces: []string{"demo"}}
	ref := api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "app", UID: "uid"}
	task := api.TaskSpec{TargetRef: ref, Mode: "HumanApproved"}
	p := api.PlanSpec{TargetRef: ref, PolicyDigest: PolicyDigest(c), Actions: []api.Action{{ID: "image", Type: "PatchResource", Target: ref, Patch: []api.PatchOp{{Op: "replace", Path: "/spec/containers/0/image", Value: "working"}}}}, Verification: api.Verification{Type: "PodRecovery", TimeoutSeconds: 180, StableWindowSeconds: 10}}
	if err := ValidatePlan(task, p, c); err != nil {
		t.Fatal(err)
	}
	p.Verification.Type = "DeploymentRecovery"
	if ValidatePlan(task, p, c) == nil {
		t.Fatal("wrong workload verifier accepted")
	}
}

func TestOperatorInfrastructureIsNeverARepairTarget(t *testing.T) {
	c := Config{Authorization: "RBAC", Namespaces: []string{"demo"}}
	operator := testkit.Resource("apps/v1", "Deployment", "demo", "agent-executor", "uid", map[string]any{"spec": map[string]any{"replicas": int64(1)}})
	operator.SetLabels(map[string]string{api.OperatorLabel: api.OperatorLabelValue})
	restart := api.Action{ID: "restart", Type: "RestartWorkload", Target: api.TargetRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "demo", Name: "agent-executor", UID: "uid"}}
	if err := AuthorizeAction(restart, operator, c); err == nil || !strings.Contains(err.Error(), "operator infrastructure") {
		t.Fatalf("restart of operator workload authorized: %v", err)
	}
	plain := testkit.Resource("v1", "ConfigMap", "demo", "settings", "cm", map[string]any{"data": map[string]any{}})
	adopt := api.Action{ID: "adopt", Type: "PatchResource", Target: api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "settings", UID: "cm"}, Patch: []api.PatchOp{{Op: "add", Path: "/metadata/labels", Value: map[string]any{api.OperatorLabel: api.OperatorLabelValue}}}}
	if err := AuthorizeAction(adopt, plain, c); err == nil || !strings.Contains(err.Error(), "operator infrastructure") {
		t.Fatalf("patch adopting the operator label authorized: %v", err)
	}
	create := api.Action{ID: "create", Type: "CreateResource", Target: api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "demo", Name: "fake-agent"}, Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "fake-agent", "namespace": "demo", "labels": map[string]any{api.OperatorLabel: api.OperatorLabelValue}}}}
	if err := AuthorizeAction(create, nil, c); err == nil || !strings.Contains(err.Error(), "operator infrastructure") {
		t.Fatalf("create impersonating operator infrastructure authorized: %v", err)
	}
}

func TestDataDeletionIsNeverARepair(t *testing.T) {
	c := Config{Authorization: "RBAC", Namespaces: []string{"demo"}}
	claim := testkit.Resource("v1", "PersistentVolumeClaim", "demo", "archive", "uid", map[string]any{"spec": map[string]any{"storageClassName": "longhorm"}})
	remove := api.Action{ID: "recreate", Type: "DeleteResource", Target: api.TargetRef{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: "demo", Name: "archive", UID: "uid"}}
	if err := AuthorizeAction(remove, claim, c); err == nil || !strings.Contains(err.Error(), "destroys its data") {
		t.Fatalf("PVC deletion authorized: %v", err)
	}
}

func claim(phase, volume string) *unstructured.Unstructured {
	return testkit.Resource("v1", "PersistentVolumeClaim", "demo", "data", "uid", map[string]any{"spec": map[string]any{"volumeName": volume, "storageClassName": "slow", "resources": map[string]any{"requests": map[string]any{"storage": "1Gi"}}}, "status": map[string]any{"phase": phase}})
}

func TestStorageRepairsAreOptIn(t *testing.T) {
	c := Config{Authorization: "RBAC", Namespaces: []string{"demo"}}
	ref := api.TargetRef{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: "demo", Name: "data", UID: "uid"}
	remove := api.Action{ID: "replace", Type: "DeleteResource", Target: ref}
	grow := api.Action{ID: "grow", Type: "PatchResource", Target: ref, Patch: []api.PatchOp{{Op: "replace", Path: "/spec/resources/requests/storage", Value: "2Gi"}}}
	if AuthorizeAction(remove, claim("Pending", ""), c) == nil || AuthorizeAction(grow, claim("Bound", "pv-1"), c) == nil {
		t.Fatal("storage repair allowed without opt-in")
	}
	c.Repairs.Storage = StorageRepairs{ReplaceUnboundClaims: true, ExpandClaims: true}
	if err := AuthorizeAction(remove, claim("Pending", ""), c); err != nil {
		t.Fatalf("never-bound claim not replaceable: %v", err)
	}
	if err := AuthorizeAction(remove, claim("Bound", "pv-1"), c); err == nil || !strings.Contains(err.Error(), "may hold data") {
		t.Fatalf("bound claim deletable: %v", err)
	}
	if err := AuthorizeAction(grow, claim("Bound", "pv-1"), c); err != nil {
		t.Fatalf("expansion refused: %v", err)
	}
	shrink := grow
	shrink.Patch = []api.PatchOp{{Op: "replace", Path: "/spec/resources/requests/storage", Value: "512Mi"}}
	class := grow
	class.Patch = []api.PatchOp{{Op: "replace", Path: "/spec/storageClassName", Value: "fast"}}
	if AuthorizeAction(shrink, claim("Bound", "pv-1"), c) == nil || AuthorizeAction(class, claim("Bound", "pv-1"), c) == nil {
		t.Fatal("claim patch beyond storage growth allowed")
	}
	volume := api.Action{ID: "pv", Type: "DeleteResource", Target: api.TargetRef{APIVersion: "v1", Kind: "PersistentVolume", Name: "pv-1", Namespace: "demo", UID: "pv"}}
	if AuthorizeAction(volume, testkit.Resource("v1", "PersistentVolume", "demo", "pv-1", "pv", nil), c) == nil {
		t.Fatal("PersistentVolume targeted")
	}
}

func TestSecretCreationIsOptInAndValueFree(t *testing.T) {
	c := Config{Authorization: "RBAC", Namespaces: []string{"demo"}}
	ref := api.TargetRef{APIVersion: "v1", Kind: "Secret", Namespace: "demo", Name: "db"}
	create := func(sources map[string]api.SecretSource, extra map[string]any) api.Action {
		object := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "db", "namespace": "demo"}}
		for k, v := range extra {
			object[k] = v
		}
		return api.Action{ID: "secret", Type: "CreateResource", Target: ref, Object: object, SecretSources: sources}
	}
	generated := map[string]api.SecretSource{"password": {Generate: 32}}
	copied := map[string]api.SecretSource{"password": {FromSecret: "db-template", FromKey: "password"}}
	if AuthorizeAction(create(generated, nil), nil, c) == nil {
		t.Fatal("Secret created without opt-in")
	}
	c.Repairs.Secrets = SecretRepairs{Create: "generate+fromSource", Sources: []string{"db-template"}}
	for name, a := range map[string]api.Action{"generated": create(generated, nil), "copied": create(copied, nil)} {
		if err := AuthorizeAction(a, nil, c); err != nil {
			t.Fatalf("%s Secret refused: %v", name, err)
		}
	}
	for name, a := range map[string]api.Action{
		"model-written value":  create(generated, map[string]any{"stringData": map[string]any{"password": "hunter2"}}),
		"unlisted source":      create(map[string]api.SecretSource{"password": {FromSecret: "agent-llm", FromKey: "api-key"}}, nil),
		"weak generated value": create(map[string]api.SecretSource{"password": {Generate: 4}}, nil),
		"no keys":              create(nil, nil),
	} {
		if AuthorizeAction(a, nil, c) == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	patch := api.Action{ID: "rotate", Type: "PatchResource", Target: api.TargetRef{APIVersion: "v1", Kind: "Secret", Namespace: "demo", Name: "db", UID: "uid"}, Patch: []api.PatchOp{{Op: "replace", Path: "/data/password", Value: "eA=="}}}
	if AuthorizeAction(patch, testkit.Resource("v1", "Secret", "demo", "db", "uid", map[string]any{"data": map[string]any{"password": "eA=="}}), c) == nil {
		t.Fatal("existing Secret changed")
	}
}
