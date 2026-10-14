package api

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"testing"
)

func samplePlan() PlanSpec {
	return PlanSpec{TaskRef: ObjectRef{Name: "fix", UID: "task-uid"}, TaskGeneration: 1,
		TargetRef:    TargetRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "demo", Name: "api", UID: "target-uid"},
		PolicyDigest: "policy-a", Preconditions: Preconditions{SpecDigest: "spec-a"},
		Diagnosis: "broken config", Risk: "disruptive",
		Actions:      []Action{{ID: "repair-1", Type: "PatchResource", Patch: []PatchOp{{Op: "replace", Path: "/spec/replicas", Value: float64(1)}}}},
		Verification: Verification{Type: "DeploymentRecovery", TimeoutSeconds: 300, StableWindowSeconds: 120}}
}

func TestDigestPlanBindsAuthorization(t *testing.T) {
	base := samplePlan()
	digest, err := DigestPlan(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Digest = digest
	same, _ := DigestPlan(base)
	if same != digest {
		t.Fatal("digest must exclude its own field")
	}
	changes := map[string]func(*PlanSpec){
		"task":         func(p *PlanSpec) { p.TaskRef.UID = "another-task" },
		"target":       func(p *PlanSpec) { p.TargetRef.UID = "another-target" },
		"generation":   func(p *PlanSpec) { p.TaskGeneration++ },
		"policy":       func(p *PlanSpec) { p.PolicyDigest = "policy-b" },
		"action":       func(p *PlanSpec) { p.Actions[0].Type = "DeleteResource" },
		"verification": func(p *PlanSpec) { p.Verification.StableWindowSeconds = 1 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p := samplePlan()
			change(&p)
			got, e := DigestPlan(p)
			if e != nil || got == digest {
				t.Fatalf("authorization change not bound: %v", e)
			}
		})
	}
}

func TestDigestTargetIgnoresStatus(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]interface{}{"name": "api", "namespace": "demo", "uid": "a", "resourceVersion": "1"}, "spec": map[string]interface{}{"replicas": int64(1)}}}
	before, e := DigestTarget(u)
	if e != nil {
		t.Fatal(e)
	}
	u.SetResourceVersion("2")
	u.Object["status"] = map[string]interface{}{"readyReplicas": int64(1)}
	after, _ := DigestTarget(u)
	if before != after {
		t.Fatal("status invalidated approval")
	}
	_ = unstructured.SetNestedField(u.Object, int64(2), "spec", "replicas")
	changed, _ := DigestTarget(u)
	if changed == before {
		t.Fatal("spec change did not invalidate approval")
	}
	u.SetUID("replacement")
	replacement, _ := DigestTarget(u)
	if replacement == changed {
		t.Fatal("UID replacement not bound")
	}
}
func TestDeploymentRevisionIsStatusButOtherAnnotationsRemainBound(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "api", "namespace": "demo", "uid": "uid", "annotations": map[string]any{"deployment.kubernetes.io/revision": "1", "policy.example.io/security": "enforced"}}, "spec": map[string]any{"replicas": int64(1)}}}
	a, _ := DigestTarget(u)
	ann := u.Object["metadata"].(map[string]any)["annotations"].(map[string]any)
	ann["deployment.kubernetes.io/revision"] = "2"
	b, _ := DigestTarget(u)
	if a != b {
		t.Fatal("controller revision invalidated authorization")
	}
	ann["policy.example.io/security"] = "disabled"
	b, _ = DigestTarget(u)
	if a == b {
		t.Fatal("security annotation was excluded")
	}
}
