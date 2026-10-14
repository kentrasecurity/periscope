package admission

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"time"
)

func (v *Validator) journal(ctx context.Context, r *admissionv1.AdmissionRequest, newObject *unstructured.Unstructured) error {
	oldObject, e := object(r.OldObject.Raw)
	if e != nil {
		return e
	}
	old, e := kube.ParsePlan(oldObject)
	if e != nil {
		return e
	}
	next, e := kube.ParsePlan(newObject)
	if e != nil {
		return e
	}
	if old.Status.ApprovalUID != "" && next.Status.ApprovalUID != old.Status.ApprovalUID {
		return fmt.Errorf("consumed approval is immutable")
	}
	if len(next.Status.Entries) < len(old.Status.Entries) || len(next.Status.Entries) > len(old.Status.Entries)+1 {
		return fmt.Errorf("journal entries cannot be removed or skipped")
	}
	if old.Status.ExecutionStartedAt != nil && (next.Status.ExecutionStartedAt == nil || !next.Status.ExecutionStartedAt.Equal(*old.Status.ExecutionStartedAt)) {
		return fmt.Errorf("execution start is immutable")
	}
	now := time.Now().UTC()
	if old.Status.ExecutionStartedAt == nil && next.Status.ExecutionStartedAt != nil && (!nearNow(*next.Status.ExecutionStartedAt, now)) {
		return fmt.Errorf("execution start must be current")
	}
	if next.Status.StableSince != nil {
		if old.Status.StableSince != nil && old.Status.VerificationFingerprint != next.Status.VerificationFingerprint && next.Status.StableSince.Equal(*old.Status.StableSince) {
			return fmt.Errorf("changed fingerprint requires a fresh stable window")
		}
		if old.Status.StableSince == nil && !nearNow(*next.Status.StableSince, now) {
			return fmt.Errorf("stable window cannot be backdated")
		}
		if old.Status.StableSince != nil && !next.Status.StableSince.Equal(*old.Status.StableSince) && !(next.Status.VerificationFingerprint != old.Status.VerificationFingerprint && nearNow(*next.Status.StableSince, now)) {
			return fmt.Errorf("stable window cannot be rewritten")
		}
	}
	for n, entry := range old.Status.Entries {
		other := next.Status.Entries[n]
		if entry.ID != other.ID || entry.Operation != other.Operation || entry.BeforeDigest != other.BeforeDigest || entry.AfterDigest != other.AfterDigest || (entry.ResultUID != "" && entry.ResultUID != other.ResultUID) || (entry.ServerResultDigest != "" && entry.ServerResultDigest != other.ServerResultDigest) {
			return fmt.Errorf("journal authorization fields are immutable")
		}
		valid := entry.State == other.State || (entry.State == "Pending" && other.State == "Applied") || (entry.State == "Applied" && other.State == "Verified")
		if !valid {
			return fmt.Errorf("invalid journal state transition")
		}
	}
	if (old.Status.Phase == "Succeeded" || old.Status.Phase == "Failed") && next.Status.Phase != old.Status.Phase {
		return fmt.Errorf("terminal execution cannot be reopened")
	}
	if next.Status.Phase == "Failed" {
		return nil
	} // Reporting an execution error never authorizes a resource mutation.
	task, e := v.Backend.GetTask(ctx, r.Namespace, next.Spec.TaskRef.Name)
	if e != nil {
		return fmt.Errorf("journal task unavailable")
	}
	current, e := v.Backend.Get(ctx, next.Spec.TargetRef)
	if apierrors.IsNotFound(e) {
		current = nil
	} else if e != nil {
		return fmt.Errorf("journal target unavailable")
	}
	approvals, e := kube.CurrentApprovals(ctx, v.Backend, next)
	if e != nil {
		return e
	}
	authorized := false
	authorizationPlan := *next
	// Authorize the transition from its prior state. The requested terminal state
	// is checked separately below and must not be treated as an approval replay.
	authorizationPlan.Status.Phase = old.Status.Phase
	for _, a := range approvals {
		if string(a.Object.GetUID()) == next.Status.ApprovalUID && executor.ValidateApprovalSet(ctx, v.Backend, task, &authorizationPlan, a, v.Policy, now) == nil {
			authorized = true
			break
		}
	}
	if !authorized {
		return fmt.Errorf("journal lacks a valid matching approval")
	}
	if len(next.Status.Entries) > len(old.Status.Entries) {
		entry := next.Status.Entries[len(old.Status.Entries)]
		index := len(old.Status.Entries)
		if index >= len(next.Spec.Actions) {
			return fmt.Errorf("extra journal action")
		}
		action := next.Spec.Actions[index]
		if entry.State != "Pending" || entry.ID != action.ID || entry.Operation != executor.Operation(next, action.ID) || !nearNow(entry.UpdatedAt, now) {
			return fmt.Errorf("invalid action intent")
		}
		current, e = executor.ReadTarget(ctx, v.Backend, action.Target)
		if e != nil {
			return e
		}
		baseline, err := executor.ActionBaseline(&authorizationPlan, index)
		if err != nil {
			return err
		}

		actual := "absent"
		if current != nil {
			actual, _ = api.DigestTarget(current)
		}
		if entry.BeforeDigest != actual || entry.BeforeDigest != baseline {
			return fmt.Errorf("journal baseline differs from immutable plan history")
		}
		if e = policy.AuthorizeAction(action, current, v.Policy); e != nil {
			return e
		}
		desired, e := executor.PrepareResult(next, action, current)
		if e != nil {
			return e
		}
		digest, _ := executor.ResultDigest(desired, action)
		if digest != entry.AfterDigest {
			return fmt.Errorf("journal result differs from approved action")
		}
	}
	for n, prior := range old.Status.Entries {
		entry := next.Status.Entries[n]
		if entry.State == prior.State {
			continue
		}
		if entry.State == "Verified" {
			if next.Status.Phase != "Succeeded" || len(next.Status.Entries) != len(next.Spec.Actions) {
				return fmt.Errorf("verification requires complete terminal recovery")
			}
			superseded := false
			for k := n + 1; k < len(next.Spec.Actions); k++ {
				if api.ResourceKey(next.Spec.Actions[k].Target) == api.ResourceKey(next.Spec.Actions[n].Target) {
					superseded = true
				}
			}
			if superseded {
				continue
			} // Earlier applied states form the immutable chain; the final object reflects the last action.
		}
		action := next.Spec.Actions[n]
		current, e = executor.ReadTarget(ctx, v.Backend, action.Target)
		if e != nil {
			return e
		}
		digest, _ := executor.ResultDigest(current, action)
		if digest != entry.AfterDigest || (current != nil && current.GetAnnotations()[api.OperationAnnotation] != entry.Operation) {
			return fmt.Errorf("journal action has not been observed applied")
		}
		if current != nil && entry.ResultUID != string(current.GetUID()) {
			return fmt.Errorf("journal result UID mismatch")
		}
	}
	current, e = executor.ReadTarget(ctx, v.Backend, next.Spec.TargetRef)
	if e != nil {
		return e
	}
	goalHealthy := false
	if next.Status.StableSince != nil || next.Status.Phase == "Succeeded" {
		var err error
		goalHealthy, err = v.planHealthy(ctx, next, task)
		if err != nil {
			return err
		}
	}
	if next.Status.StableSince != nil {
		if next.Spec.Verification.Type == "DeploymentRecovery" && len(next.Spec.Checks) == 0 {
			ok, fingerprint, err := executor.CheckPods(ctx, v.Backend, current)
			if err != nil || !ok || fingerprint != next.Status.VerificationFingerprint {
				return fmt.Errorf("Pod recovery fingerprint unavailable or changed")
			}
			if old.Status.StableSince != nil && next.Status.StableSince.Equal(*old.Status.StableSince) && old.Status.VerificationFingerprint != fingerprint {
				return fmt.Errorf("Pod changes require a new stable window")
			}
		}
		if len(next.Status.Entries) != len(next.Spec.Actions) {
			return fmt.Errorf("stable verification requires all planned actions")
		}
		for _, entry := range next.Status.Entries {
			if entry.State != "Applied" && entry.State != "Verified" {
				return fmt.Errorf("stable verification requires applied actions")
			}
		}
		if !goalHealthy {
			return fmt.Errorf("stable verification requires current application recovery")
		}
	}
	if next.Status.Phase == "Succeeded" {
		if old.Status.Phase != "Verifying" || old.Status.StableSince == nil || now.Sub(*old.Status.StableSince) < time.Duration(next.Spec.Verification.StableWindowSeconds)*time.Second {
			return fmt.Errorf("stable recovery window incomplete")
		}
		for _, entry := range next.Status.Entries {
			if entry.State != "Verified" {
				return fmt.Errorf("unverified action cannot succeed")
			}
		}
		if !goalHealthy {
			return fmt.Errorf("original failure is not verified resolved")
		}
	}
	return nil
}
func nearNow(t, now time.Time) bool {
	return !t.Before(now.Add(-10*time.Second)) && !t.After(now.Add(10*time.Second))
}

func (v *Validator) planHealthy(ctx context.Context, p *kube.Plan, t *kube.Task) (bool, error) {
	checks := p.Spec.Checks
	if len(checks) == 0 {
		checks = []api.Check{api.VerificationCheck(p.Spec.TargetRef, p.Spec.Verification)}
	}
	checker := v.Checker
	checker.Reader = v.Backend
	checker.Pods = v.Backend
	if t.Spec.Scope != nil {
		checker.Scope = *t.Spec.Scope
	} else {
		checker.Scope = api.Scope{Namespaces: []string{p.Spec.TargetRef.Namespace}}
	}
	results, err := checker.EvaluateChecks(ctx, checks)
	if err != nil {
		return false, err
	}
	if len(p.Spec.Checks) > 0 && executor.ChecksFingerprint(results) != p.Status.VerificationFingerprint {
		return false, fmt.Errorf("original check fingerprint changed")
	}
	if len(p.Spec.Checks) == 0 && p.Spec.Verification.Type == "PodRecovery" && results[0].Fingerprint != p.Status.VerificationFingerprint {
		return false, fmt.Errorf("Pod runtime changed")
	}
	return executor.ChecksHealthy(results), nil
}
