package admission

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"testing"
)

func TestHumanDecisionOnlyAndNoOperatorSelfApproval(t *testing.T) {
	v, b, r := requestSetup(t)
	a := b.ApprovalItems["demo/approve"]
	a.Spec.Decision = "Pending"
	old := map[string]any{"apiVersion": api.Group + "/" + api.Version, "kind": "ActionApproval", "spec": kube.JSONMap(a.Spec)}
	next := kube.JSONMap(old)
	next["spec"].(map[string]any)["decision"] = "Approve"
	r.Request.Resource = metav1.GroupVersionResource{Group: api.Group, Version: api.Version, Resource: "actionapprovals"}
	r.Request.Kind = metav1.GroupVersionKind{Group: api.Group, Version: api.Version, Kind: "ActionApproval"}
	r.Request.Operation = admissionv1.Update
	r.Request.UserInfo.Username = "human"
	r.Request.OldObject = runtime.RawExtension{}
	r.Request.OldObject.Raw, _ = json.Marshal(old)
	r.Request.Object.Raw, _ = json.Marshal(next)
	if got := v.Validate(context.Background(), r); !got.Allowed {
		t.Fatal(got.Result)
	}
	r.Request.UserInfo.Username = v.InvestigatorUser
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("investigator approved human task")
	}
	r.Request.UserInfo.Username = "human"
	next["spec"].(map[string]any)["planUID"] = "other"
	r.Request.Object.Raw, _ = json.Marshal(next)
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("decision changed binding")
	}
}
func TestOperatorCannotChangeTaskModeToAuthorizeItself(t *testing.T) {
	v, _, r := requestSetup(t)
	r.Request.Kind = metav1.GroupVersionKind{Group: api.Group, Version: api.Version, Kind: "AgentTask"}
	r.Request.Resource.Group = api.Group
	r.Request.Resource.Resource = "agenttasks"
	r.Request.UserInfo.Username = v.InvestigatorUser
	r.Request.Object.Raw = []byte(`{"spec":{"targetRef":{"apiVersion":"v1","kind":"ConfigMap","name":"settings"},"mode":"Automatic","objective":"fix","limits":{"deadlineSeconds":600,"maxModelCalls":5,"maxToolCalls":30}}}`)
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("operator could change user-controlled task mode")
	}
}

func TestExecutorCannotRestoreSupersededCurrentPlan(t *testing.T) {
	v, b, r := requestSetup(t)
	v.Policy.Authorization = "RBAC"
	task := b.Tasks["demo/fix"]
	old := task.Object.DeepCopy()
	old.Object["spec"] = kube.JSONMap(task.Spec)
	status := task.Status
	status.Cycle = 2
	status.PlanRef = &api.ObjectRef{Name: "new", UID: "new-uid"}
	old.Object["status"] = kube.JSONMap(status)
	next := old.DeepCopy()
	next.Object["status"].(map[string]any)["planRef"] = map[string]any{"name": "plan", "uid": "plan-plan"}
	r.Request.Name = "fix"
	r.Request.Kind = metav1.GroupVersionKind{Group: api.Group, Version: api.Version, Kind: "AgentTask"}
	r.Request.Resource = metav1.GroupVersionResource{Group: api.Group, Version: api.Version, Resource: "agenttasks"}
	r.Request.SubResource = "status"
	r.Request.UserInfo.Username = v.ExecutorUser
	r.Request.OldObject.Raw, _ = json.Marshal(old.Object)
	r.Request.Object.Raw, _ = json.Marshal(next.Object)
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("executor restored superseded plan")
	}
}

func TestInvestigatorStatusAcceptsSerializedGeneration(t *testing.T) {
	v, b, r := requestSetup(t)
	task := b.Tasks["demo/fix"]
	old := task.Object.DeepCopy()
	old.Object["spec"] = kube.JSONMap(task.Spec)
	old.Object["status"] = kube.JSONMap(task.Status)
	next := old.DeepCopy()
	next.Object["status"].(map[string]any)["report"] = "poll completed"
	r.Request.Name = "fix"
	r.Request.Kind = metav1.GroupVersionKind{Group: api.Group, Version: api.Version, Kind: "AgentTask"}
	r.Request.Resource = metav1.GroupVersionResource{Group: api.Group, Version: api.Version, Resource: "agenttasks"}
	r.Request.SubResource = "status"
	r.Request.UserInfo.Username = v.InvestigatorUser
	r.Request.OldObject.Raw, _ = json.Marshal(old.Object)
	r.Request.Object.Raw, _ = json.Marshal(next.Object)
	if got := v.Validate(context.Background(), r); !got.Allowed {
		t.Fatalf("valid serialized status rejected: %v", got.Result)
	}
}
