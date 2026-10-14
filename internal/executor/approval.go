package executor

import (
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"time"
)

func ValidateApproval(task *kube.Task, p *kube.Plan, a *kube.Approval, target *unstructured.Unstructured, c policy.Config, now time.Time) error {
	if task == nil || p == nil || a == nil {
		return fmt.Errorf("task, plan and approval required")
	}
	if task.Spec.Suspend {
		return fmt.Errorf("task is suspended")
	}
	if a.Spec.Decision != "" && a.Spec.Decision != "Approve" {
		return fmt.Errorf("approval decision required")
	}
	if task.Spec.Mode != "HumanApproved" && task.Spec.Mode != "Automatic" {
		return fmt.Errorf("execution requires human-approved mode")
	}
	if task.Object.GetNamespace() != p.Object.GetNamespace() || a.Object.GetNamespace() != p.Object.GetNamespace() {
		return fmt.Errorf("approval namespace mismatch")
	}
	if p.Spec.TaskRef.UID != string(task.Object.GetUID()) || p.Spec.TaskRef.Name != task.Object.GetName() || p.Spec.TaskGeneration != task.Object.GetGeneration() || task.Status.ObservedGeneration != task.Object.GetGeneration() {
		return fmt.Errorf("task intent changed")
	}
	if p.Spec.IncidentID != "" {
		if task.Status.Incident == nil || task.Status.Incident.ID != p.Spec.IncidentID || task.Status.Incident.OriginalChecksDigest != p.Spec.OriginalChecksDigest {
			return fmt.Errorf("incident authorization changed")
		}
	}
	if p.Spec.IncidentID != "" && len(p.Spec.Checks) > 0 {
		digest, _ := api.Hash(p.Spec.Checks)
		if digest != task.Status.Incident.OriginalChecksDigest {
			return fmt.Errorf("plan changed original checks")
		}
	}
	if p.Spec.IncidentID != "" && len(p.Spec.Checks) == 0 && len(task.Status.Incident.OriginalChecks) != 1 {
		return fmt.Errorf("original incident checks missing from plan")
	}
	if p.Spec.IncidentID != "" && len(p.Spec.Checks) == 0 && len(task.Status.Incident.OriginalChecks) == 1 {
		check := api.VerificationCheck(p.Spec.TargetRef, p.Spec.Verification)
		digest, _ := api.Hash([]api.Check{check})
		if digest != task.Status.Incident.OriginalChecksDigest {
			return fmt.Errorf("repair weakened original incident checks")
		}
	}
	if task.Status.Cycle != p.Spec.TaskCycle {
		return fmt.Errorf("plan monitoring cycle changed")
	}
	if task.Status.PlanRef == nil || task.Status.PlanRef.UID != string(p.Object.GetUID()) || task.Status.PlanRef.Name != p.Object.GetName() {
		return fmt.Errorf("plan is not the current task plan")
	}
	digest, e := api.DigestPlan(p.Spec)
	if e != nil || digest != p.Spec.Digest {
		return fmt.Errorf("plan integrity check failed")
	}
	if a.Spec.TaskUID != string(task.Object.GetUID()) || a.Spec.PlanUID != string(p.Object.GetUID()) || a.Spec.PlanDigest != digest {
		return fmt.Errorf("approval does not bind this exact plan")
	}
	created := a.Object.GetCreationTimestamp().Time
	if created.IsZero() {
		return fmt.Errorf("approval creation timestamp required")
	}
	if !a.Spec.ExpiresAt.After(now) || !a.Spec.ExpiresAt.After(created) || a.Spec.ExpiresAt.After(created.Add(30*time.Minute)) {
		return fmt.Errorf("approval expired or exceeded maximum lifetime")
	}
	if p.Status.Phase == "Succeeded" || p.Status.Phase == "Failed" || task.Status.Phase == "Succeeded" || task.Status.Phase == "Cancelled" || task.Status.Phase == "Failed" {
		return fmt.Errorf("terminal authorization cannot be replayed")
	}
	if p.Status.ApprovalUID != "" && p.Status.ApprovalUID != string(a.Object.GetUID()) {
		return fmt.Errorf("approval identity changed after consumption")
	}
	spec := task.Spec
	if spec.TargetRef.Namespace == "" {
		spec.TargetRef.Namespace = task.Object.GetNamespace()
	}
	if e = policy.ValidatePlan(spec, p.Spec, c); e != nil {
		return e
	}
	if len(p.Spec.Targets) > 0 {
		return nil
	} // Bound objects are validated together by ValidateApprovalSet.
	if target == nil {
		if len(p.Spec.Actions) == 1 && p.Spec.Actions[0].Type == "CreateResource" && p.Spec.Preconditions.SpecDigest == "absent" {
			return nil
		}
		if len(p.Spec.Actions) == 1 && p.Spec.Actions[0].Type == "DeleteResource" && p.Status.ApprovalUID == string(a.Object.GetUID()) {
			for _, entry := range p.Status.Entries {
				if entry.ID == p.Spec.Actions[0].ID && entry.AfterDigest == "absent" {
					return nil
				}
			}
		}
		return fmt.Errorf("target missing outside approved recovery")
	}
	if task.Spec.Scope != nil && !task.Spec.Scope.Matches(p.Spec.TargetRef, target) {
		return fmt.Errorf("target no longer matches task scope")
	}
	if target.GetNamespace() != p.Spec.TargetRef.Namespace || target.GetName() != p.Spec.TargetRef.Name || target.GetAPIVersion() != p.Spec.TargetRef.APIVersion || target.GetKind() != p.Spec.TargetRef.Kind {
		return fmt.Errorf("target identity changed")
	}
	if p.Spec.TargetRef.UID == "" && len(p.Spec.Actions) == 1 && p.Spec.Actions[0].Type == "CreateResource" && p.Status.ApprovalUID == string(a.Object.GetUID()) {
		digest, _ := ResultDigest(target, p.Spec.Actions[0])
		for _, entry := range p.Status.Entries {
			if entry.ID == p.Spec.Actions[0].ID && entry.AfterDigest == digest && creationUnchanged(target, p.Spec.Actions[0], entry) && target.GetAnnotations()[api.OperationAnnotation] == entry.Operation && (entry.ResultUID == "" || entry.ResultUID == string(target.GetUID())) {
				return nil
			}
		}
		return fmt.Errorf("created resource does not match approved recovery")
	}
	if string(target.GetUID()) != p.Spec.TargetRef.UID {
		return fmt.Errorf("target UID changed")
	}
	current, e := api.DigestTarget(target)
	if e != nil {
		return e
	}
	allowed := current == p.Spec.Preconditions.SpecDigest
	if !allowed && p.Status.ApprovalUID == string(a.Object.GetUID()) {
		for _, entry := range p.Status.Entries {
			if entry.AfterDigest != "" && entry.AfterDigest == current && (entry.State == "Pending" || entry.State == "Applied" || entry.State == "Verified") {
				allowed = true
			}
		}
	}
	if !allowed {
		return fmt.Errorf("target configuration changed outside approved execution")
	}
	return nil
}
