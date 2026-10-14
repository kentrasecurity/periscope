package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"strings"
	"time"
)

type ReadBackend interface {
	executor.PodReader
	Get(context.Context, api.TargetRef) (*unstructured.Unstructured, error)
	GetTask(context.Context, string, string) (*kube.Task, error)
	GetPlan(context.Context, string, string) (*kube.Plan, error)
	ListPlans(context.Context, string) ([]*kube.Plan, error)
	Approvals(context.Context, string) ([]*kube.Approval, error)
	HasClaim(context.Context, string, string, string) (bool, error)
}
type Validator struct {
	Checker                        executor.CheckEvaluator
	Backend                        ReadBackend
	Policy                         policy.Config
	InvestigatorUser, ExecutorUser string
}

func (v *Validator) Validate(ctx context.Context, review admissionv1.AdmissionReview) admissionv1.AdmissionResponse {
	response := admissionv1.AdmissionResponse{Allowed: false}
	if review.Request == nil {
		response.Result = &metav1.Status{Message: "admission request required", Code: 400}
		return response
	}
	response.UID = review.Request.UID
	if e := v.validate(ctx, review.Request); e != nil {
		response.Result = &metav1.Status{Message: e.Error(), Code: 403}
		return response
	}
	response.Allowed = true
	return response
}
func object(raw []byte) (*unstructured.Unstructured, error) {
	var m map[string]any
	if e := json.Unmarshal(raw, &m); e != nil {
		return nil, fmt.Errorf("invalid admission object")
	}
	return &unstructured.Unstructured{Object: m}, nil
}
func (v *Validator) validate(ctx context.Context, r *admissionv1.AdmissionRequest) error {
	if r.Resource.Group == api.Group {
		return v.contract(ctx, r)
	}
	if r.UserInfo.Username == v.InvestigatorUser {
		return fmt.Errorf("investigator identity has no workload mutation authority")
	}
	if r.UserInfo.Username != v.ExecutorUser {
		return nil
	}
	if r.SubResource != "" {
		return fmt.Errorf("executor workload subresources are forbidden")
	}
	if r.Resource.Group == "coordination.k8s.io" && r.Resource.Resource == "leases" && strings.HasPrefix(r.Name, "periscope-") {
		return v.lease(ctx, r)
	}
	if r.Operation != admissionv1.Update && r.Operation != admissionv1.Create && r.Operation != admissionv1.Delete {
		return fmt.Errorf("unsupported executor operation")
	}
	var before, after *unstructured.Unstructured
	var e error
	if r.Operation != admissionv1.Create {
		before, e = object(r.OldObject.Raw)
		if e != nil {
			return e
		}
	}
	if r.Operation != admissionv1.Delete {
		after, e = object(r.Object.Raw)
		if e != nil {
			return e
		}
	}
	var plans []*kube.Plan
	if after != nil {
		name := after.GetAnnotations()[api.Group+"/plan"]
		if name == "" {
			return fmt.Errorf("executor mutation requires an approved plan reference")
		}
		recordNS := after.GetAnnotations()[api.Group+"/plan-namespace"]
		if recordNS == "" {
			recordNS = r.Namespace
		}
		p, err := v.Backend.GetPlan(ctx, recordNS, name)
		if err != nil {
			return fmt.Errorf("referenced plan unavailable")
		}
		plans = []*kube.Plan{p}
	} else {
		for _, ns := range v.Policy.Namespaces {
			items, err := kube.CurrentPlans(ctx, v.Backend, ns)
			if err != nil {
				return fmt.Errorf("delete plans unavailable")
			}
			plans = append(plans, items...)
		}
	}
	for _, p := range plans {
		if e = v.validateMutation(ctx, r, p, before, after); e == nil {
			return nil
		}
	}
	return fmt.Errorf("mutation does not match a current approved action, target claim and journal")
}
func (v *Validator) validateMutation(ctx context.Context, r *admissionv1.AdmissionRequest, p *kube.Plan, before, after *unstructured.Unstructured) error {
	version := r.Resource.Version
	if r.Resource.Group != "" {
		version = r.Resource.Group + "/" + version
	}
	recordNS := p.Object.GetNamespace()
	t, e := v.Backend.GetTask(ctx, recordNS, p.Spec.TaskRef.Name)
	if e != nil {
		return fmt.Errorf("task unavailable")
	}
	approvals, e := kube.CurrentApprovals(ctx, v.Backend, p)
	if e != nil {
		return fmt.Errorf("approval unavailable")
	}
	approved := false
	for _, a := range approvals {
		if string(a.Object.GetUID()) == p.Status.ApprovalUID && executor.ValidateApprovalSet(ctx, v.Backend, t, p, a, v.Policy, time.Now().UTC()) == nil {
			approved = true
			break
		}
	}
	if !approved {
		return fmt.Errorf("no valid consumed approval")
	}
	for _, claim := range executor.ClaimKeys(p) {
		held, err := v.Backend.HasClaim(ctx, executor.ClaimNamespace(p, v.Policy), claim, string(p.Object.GetUID()))
		if err != nil || !held {
			return fmt.Errorf("no live target claim")
		}
	}
	for actionIndex, a := range p.Spec.Actions {
		if a.Target.Namespace != r.Namespace || a.Target.Name != r.Name || a.Target.Kind != r.Kind.Kind || a.Target.APIVersion != version {
			continue
		}
		expectedOperation := admissionv1.Update
		if a.Type == "CreateResource" {
			expectedOperation = admissionv1.Create
		}
		if a.Type == "DeleteResource" {
			expectedOperation = admissionv1.Delete
		}
		if r.Operation != expectedOperation {
			continue
		}
		cap, e := v.Policy.Find(a)
		if e != nil || (!v.Policy.RBAC() && cap.Resource != r.Resource.Resource) {
			continue
		}
		if e = policy.AuthorizeAction(a, before, v.Policy); e != nil {
			continue
		}
		for _, entry := range p.Status.Entries {
			if entry.ID != a.ID || entry.State != "Pending" || entry.Operation != executor.Operation(p, a.ID) {
				continue
			}
			beforeDigest := "absent"
			if before != nil {
				beforeDigest, _ = api.DigestTarget(before)
			}
			baseline, err := executor.ActionBaseline(p, actionIndex)
			if err != nil {
				continue
			}
			if entry.BeforeDigest != beforeDigest || entry.BeforeDigest != baseline {
				continue
			}
			desired, e := executor.PrepareResult(p, a, before)
			if e != nil {
				continue
			}
			want, _ := executor.ResultDigest(desired, a)
			actual, _ := executor.ResultDigest(after, a)
			if want == actual && entry.AfterDigest == want && (a.Type == "CreateResource" || executor.SameAnnotations(desired, after)) {
				return nil
			}
		}
	}
	return fmt.Errorf("request is not the expected pending result")
}

func (v *Validator) contract(ctx context.Context, r *admissionv1.AdmissionRequest) error {
	if r.Operation == admissionv1.Delete {
		return nil
	}
	u, e := object(r.Object.Raw)
	if e != nil {
		return e
	}
	if r.Operation == admissionv1.Update && (r.Kind.Kind == "ActionPlan" || r.Kind.Kind == "ActionApproval") {
		old, e := object(r.OldObject.Raw)
		if e != nil {
			return e
		}
		left, _, _ := unstructured.NestedMap(old.Object, "spec")
		right, _, _ := unstructured.NestedMap(u.Object, "spec")
		if r.Kind.Kind == "ActionApproval" {
			oldDecision, _ := left["decision"].(string)
			nextDecision, _ := right["decision"].(string)
			if oldDecision != nextDecision {
				if oldDecision != "Pending" || (nextDecision != "Approve" && nextDecision != "Reject") || r.UserInfo.Username == v.InvestigatorUser || r.UserInfo.Username == v.ExecutorUser {
					return fmt.Errorf("approval decision requires a human one-time Pending transition")
				}
				delete(left, "decision")
				delete(right, "decision")
			}
		}
		a, _ := api.Hash(left)
		b, _ := api.Hash(right)
		if a != b {
			return fmt.Errorf("plan and approval specs are immutable")
		}
	}
	if r.SubResource == "status" {
		if r.Kind.Kind == "ActionPlan" && r.UserInfo.Username == v.ExecutorUser {
			return v.journal(ctx, r, u)
		}
		if r.Kind.Kind == "AgentTask" && (r.UserInfo.Username == v.ExecutorUser || r.UserInfo.Username == v.InvestigatorUser) {
			return v.taskStatus(ctx, r, u)
		}
		return fmt.Errorf("status is owned by the operator identity")
	}
	switch r.Kind.Kind {
	case "AgentTask":
		if r.UserInfo.Username == v.InvestigatorUser || r.UserInfo.Username == v.ExecutorUser {
			return fmt.Errorf("task intent and mode are owner-controlled")
		}
		var spec api.TaskSpec
		if e = kube.Decode(u.Object["spec"], &spec); e != nil {
			return e
		}

		if spec.Scope == nil && spec.TargetRef.Namespace == "" {
			spec.TargetRef.Namespace = r.Namespace
		}
		return api.ValidateTask(spec)
	case "ActionPlan":
		if r.Operation != admissionv1.Create {
			return nil
		}
		if r.UserInfo.Username != v.InvestigatorUser {
			return fmt.Errorf("only investigator may create plans")
		}
		p, e := kube.ParsePlan(u)
		if e != nil {
			return e
		}
		digest, e := api.DigestPlan(p.Spec)
		if e != nil || digest != p.Spec.Digest {
			return fmt.Errorf("invalid plan digest")
		}
		t, e := v.Backend.GetTask(ctx, r.Namespace, p.Spec.TaskRef.Name)
		if e != nil {
			return fmt.Errorf("plan task unavailable")
		}
		if p.Spec.TaskRef.UID != string(t.Object.GetUID()) || p.Spec.TaskGeneration != t.Object.GetGeneration() || p.Spec.TaskCycle != t.Status.Cycle {
			return fmt.Errorf("plan task intent differs")
		}
		spec := t.Spec
		if spec.TargetRef.Namespace == "" {
			spec.TargetRef.Namespace = r.Namespace
		}
		return policy.ValidatePlan(spec, p.Spec, v.Policy)
	case "ActionApproval":
		if r.Operation != admissionv1.Create && r.Operation != admissionv1.Update {
			return nil
		}
		var a api.ApprovalSpec
		if e = kube.Decode(u.Object["spec"], &a); e != nil {
			return e
		}
		if a.Decision != "" && a.Decision != "Pending" && a.Decision != "Approve" && a.Decision != "Reject" {
			return fmt.Errorf("unknown approval decision")
		}
		if r.UserInfo.Username == v.ExecutorUser {
			return fmt.Errorf("executor cannot approve itself")
		}
		now := time.Now().UTC()
		if !a.ExpiresAt.After(now) || a.ExpiresAt.After(now.Add(30*time.Minute)) {
			return fmt.Errorf("approval lifetime outside permitted bounds")
		}
		var plans []*kube.Plan
		if a.PlanName != "" {
			plan, err := v.Backend.GetPlan(ctx, r.Namespace, a.PlanName)
			if err != nil {
				return fmt.Errorf("approval plan unavailable")
			}
			plans = []*kube.Plan{plan}
		} else {
			plans, e = kube.CurrentPlans(ctx, v.Backend, r.Namespace)
		}
		if e != nil {
			return e
		}
		for _, p := range plans {
			if string(p.Object.GetUID()) != a.PlanUID || p.Spec.Digest != a.PlanDigest || p.Spec.TaskRef.UID != a.TaskUID {
				continue
			}
			task, err := v.Backend.GetTask(ctx, r.Namespace, p.Spec.TaskRef.Name)
			if err != nil || (task.Spec.Mode != "HumanApproved" && task.Spec.Mode != "Automatic") || task.Spec.Suspend || string(task.Object.GetUID()) != a.TaskUID || task.Object.GetGeneration() != p.Spec.TaskGeneration || task.Status.PlanRef == nil || task.Status.PlanRef.UID != a.PlanUID || task.Status.PlanRef.Name != p.Object.GetName() || p.Spec.TaskCycle != task.Status.Cycle {
				return fmt.Errorf("approval task intent/current plan changed")
			}
			if r.Operation == admissionv1.Update && task.Status.ApprovalRef != nil && task.Status.ApprovalRef.UID != string(u.GetUID()) {
				return fmt.Errorf("approval request was superseded")
			}
			if r.UserInfo.Username == v.InvestigatorUser && (r.Operation != admissionv1.Create || (a.Decision != "Pending" && !(task.Spec.Mode == "Automatic" && a.Decision == "Approve"))) {
				return fmt.Errorf("investigator cannot approve human tasks")
			}
			if a.Decision == "Approve" && task.Spec.Mode == "Automatic" && r.UserInfo.Username != v.InvestigatorUser {
				return fmt.Errorf("automatic approval is controller-owned")
			}
			return nil
		}
		return fmt.Errorf("approval does not bind a current plan")
	default:
		return fmt.Errorf("unsupported operator resource")
	}
}
