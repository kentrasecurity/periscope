// Package testkit contains in-memory fixtures; it is never used by the deployed operator.
package testkit

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"time"
)

type Memory struct {
	Tasks          map[string]*kube.Task
	Plans          map[string]*kube.Plan
	ApprovalItems  map[string]*kube.Approval
	Resources      map[string]*unstructured.Unstructured
	Mutations      int
	ReadDenied     bool
	WriteThenError bool
	Claims         map[string]string
	// RecentLog holds recent log text by "pod/container".
	RecentLog map[string]string
}

func NewMemory() *Memory {
	return &Memory{Tasks: map[string]*kube.Task{}, Plans: map[string]*kube.Plan{}, ApprovalItems: map[string]*kube.Approval{}, Resources: map[string]*unstructured.Unstructured{}, Claims: map[string]string{}}
}
func Timestamp(t time.Time) metav1.Time { return metav1.NewTime(t) }
func Resource(version, kind, ns, name, uid string, fields map[string]any) *unstructured.Unstructured {
	o := map[string]any{"apiVersion": version, "kind": kind, "metadata": map[string]any{"name": name, "namespace": ns, "uid": uid, "generation": int64(1), "resourceVersion": "1"}}
	for k, v := range fields {
		o[k] = v
	}
	return &unstructured.Unstructured{Object: o}
}
func key(ns, name string) string { return ns + "/" + name }
func (m *Memory) PutResource(u *unstructured.Unstructured) {
	m.Resources[key(u.GetNamespace(), u.GetName())] = u
}
func (m *Memory) PutTask(ns, name, uid string, s api.TaskSpec) *kube.Task {
	t := &kube.Task{Object: Resource(api.Group+"/"+api.Version, "AgentTask", ns, name, uid, nil), Spec: s}
	m.Tasks[key(ns, name)] = t
	return t
}
func (m *Memory) GetTask(_ context.Context, ns, name string) (*kube.Task, error) {
	t, ok := m.Tasks[key(ns, name)]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: api.Group, Resource: "agenttasks"}, name)
	}
	return t, nil
}
func (m *Memory) SaveTaskStatus(_ context.Context, t *kube.Task) error {
	m.Tasks[key(t.Object.GetNamespace(), t.Object.GetName())] = t
	return nil
}
func (m *Memory) GetPlan(_ context.Context, ns, name string) (*kube.Plan, error) {
	p, ok := m.Plans[key(ns, name)]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: api.Group, Resource: "actionplans"}, name)
	}
	return p, nil
}
func (m *Memory) CreatePlan(_ context.Context, ns, name string, s api.PlanSpec) (*kube.Plan, error) {
	if _, ok := m.Plans[key(ns, name)]; ok {
		return nil, apierrors.NewAlreadyExists(schema.GroupResource{Group: api.Group, Resource: "actionplans"}, name)
	}
	p := &kube.Plan{Object: Resource(api.Group+"/"+api.Version, "ActionPlan", ns, name, "plan-"+name, nil), Spec: s}
	m.Plans[key(ns, name)] = p
	return p, nil
}
func (m *Memory) Get(_ context.Context, t api.TargetRef) (*unstructured.Unstructured, error) {
	if m.ReadDenied {
		return nil, fmt.Errorf("forbidden")
	}
	u, ok := m.Resources[key(t.Namespace, t.Name)]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: t.Kind}, t.Name)
	}
	return u.DeepCopy(), nil
}
func (m *Memory) List(_ context.Context, version, kind, ns, _ string) ([]*unstructured.Unstructured, error) {
	var out []*unstructured.Unstructured
	for _, u := range m.Resources {
		if u.GetNamespace() == ns && u.GetKind() == kind && u.GetAPIVersion() == version {
			out = append(out, u.DeepCopy())
		}
	}
	return out, nil
}
func (m *Memory) Logs(_ context.Context, _, _, _ string, _ bool, _ int64) (string, error) {
	return "", fmt.Errorf("logs unavailable")
}
func (m *Memory) RecentLogs(_ context.Context, _, pod, container string, _ int64) (string, error) {
	return m.RecentLog[pod+"/"+container], nil
}
func (m *Memory) DescribeAPI(_ context.Context, t api.TargetRef) (string, error) {
	return t.APIVersion + " " + t.Kind, nil
}

func (m *Memory) SavePlanStatus(_ context.Context, p *kube.Plan) error {
	m.Plans[key(p.Object.GetNamespace(), p.Object.GetName())] = p
	return nil
}

func (m *Memory) ListPlans(_ context.Context, namespace string) ([]*kube.Plan, error) {
	var out []*kube.Plan
	for _, p := range m.Plans {
		if p.Object.GetNamespace() == namespace {
			out = append(out, p)
		}
	}
	return out, nil
}
func (m *Memory) HasClaim(_ context.Context, _, target, holder string) (bool, error) {
	return m.Claims[target] == holder, nil
}
func (m *Memory) Approvals(_ context.Context, namespace string) ([]*kube.Approval, error) {
	var out []*kube.Approval
	for _, a := range m.ApprovalItems {
		if a.Object.GetNamespace() == namespace {
			out = append(out, a)
		}
	}
	return out, nil
}
func (m *Memory) Claim(_ context.Context, _, target, holder string) (bool, error) {
	if current := m.Claims[target]; current != "" && current != holder {
		return false, nil
	}
	m.Claims[target] = holder
	return true, nil
}
func (m *Memory) Release(_ context.Context, _, target, holder string) error {
	if m.Claims[target] == holder {
		delete(m.Claims, target)
	}
	return nil
}
func (m *Memory) Execute(_ context.Context, a api.Action, before, desired *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	var out *unstructured.Unstructured
	if desired != nil {
		out = desired.DeepCopy()
		if a.Type == "CreateResource" {
			out.SetUID(types.UID("created-" + a.Target.Name))
			out.SetResourceVersion("1")
		}
	}
	if dry {
		return out, nil
	}
	m.Mutations++
	if out == nil {
		delete(m.Resources, key(a.Target.Namespace, a.Target.Name))
	} else {
		m.PutResource(out)
	}
	if m.WriteThenError {
		return nil, fmt.Errorf("timeout after committed write")
	}
	return out, nil
}

func (m *Memory) CreateApproval(_ context.Context, ns, name string, s api.ApprovalSpec) (*kube.Approval, error) {
	if a, ok := m.ApprovalItems[key(ns, name)]; ok {
		return a, nil
	}
	a := &kube.Approval{Object: Resource(api.Group+"/"+api.Version, "ActionApproval", ns, name, "approval-"+name, nil), Spec: s}
	a.Object.SetCreationTimestamp(Timestamp(time.Now()))
	m.ApprovalItems[key(ns, name)] = a
	return a, nil
}
