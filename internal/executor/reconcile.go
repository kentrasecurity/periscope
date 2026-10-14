package executor

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"time"
)

type Backend interface {
	kube.InvestigatorBackend
	Get(context.Context, api.TargetRef) (*unstructured.Unstructured, error)
	PodReader
	SavePlanStatus(context.Context, *kube.Plan) error
	Approvals(context.Context, string) ([]*kube.Approval, error)
	Claim(context.Context, string, string, string) (bool, error)
	Release(context.Context, string, string, string) error
	Execute(context.Context, api.Action, *unstructured.Unstructured, *unstructured.Unstructured, bool) (*unstructured.Unstructured, error)
}
type Executor struct {
	Checker CheckEvaluator
	Backend Backend
	Policy  policy.Config
	Now     func() time.Time
}

func (e *Executor) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Executor) Reconcile(ctx context.Context, namespace, name string) error {
	t, err := e.Backend.GetTask(ctx, namespace, name)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if t.Spec.Suspend || (t.Spec.Mode != "HumanApproved" && t.Spec.Mode != "Automatic") || t.Status.PlanRef == nil {
		return nil
	}
	switch t.Status.Phase {
	case "Cancelled", "Blocked":
		return nil
	}
	p, err := e.Backend.GetPlan(ctx, namespace, t.Status.PlanRef.Name)
	if err != nil {
		return err
	}
	if p.Status.Phase == "Succeeded" || p.Status.Phase == "Failed" {
		if p.Spec.TaskRef.UID != string(t.Object.GetUID()) || p.Spec.TaskGeneration != t.Object.GetGeneration() || t.Status.PlanRef.UID != string(p.Object.GetUID()) || p.Spec.TaskCycle != t.Status.Cycle {
			return nil
		}
		if t.Status.Phase != p.Status.Phase {
			now := e.now()
			t.Status.Phase = p.Status.Phase
			t.Status.CompletedAt = &now
			t.Status.Conditions = api.AppendConditions(t.Status.Conditions, p.Status.Conditions...)
			if err = e.Backend.SaveTaskStatus(ctx, t); err != nil {
				return err
			}
		}
		return e.releaseAll(ctx, namespace, p)
	}
	u, err := e.Backend.Get(ctx, p.Spec.TargetRef)
	if apierrors.IsNotFound(err) {
		u = nil
	} else if err != nil {
		return err
	}
	approvals, err := kube.CurrentApprovals(ctx, e.Backend, p)
	if err != nil {
		return err
	}
	var approval *kube.Approval
	for _, a := range approvals {
		if ValidateApprovalSet(ctx, e.Backend, t, p, a, e.Policy, e.now()) == nil {
			approval = a
			break
		}
	}
	if approval == nil {
		if p.Status.ApprovalUID != "" {
			return e.fail(ctx, t, p, "AuthorizationUnavailable", "consumed approval expired, was revoked, or no longer matches current target/policy")
		}
		return nil
	}
	if !e.Policy.RBAC() && t.Status.StartedAt != nil && e.now().After(t.Status.StartedAt.Add(time.Duration(t.Spec.Limits.DeadlineSeconds)*time.Second)) {
		return e.fail(ctx, t, p, "DeadlineExceeded", "task execution deadline exceeded")
	}
	if e.Policy.RBAC() && p.Status.ExecutionStartedAt != nil && e.now().Sub(*p.Status.ExecutionStartedAt) > time.Duration(t.Spec.Limits.DeadlineSeconds)*time.Second {
		return e.fail(ctx, t, p, "DeadlineExceeded", "repair cycle execution deadline exceeded")
	}
	acquired, err := e.claimAll(ctx, namespace, p)
	if err != nil || !acquired {
		return err
	}
	// Preauthorize the complete plan before any mutation. In particular, a
	// replacement must not delete first and discover missing create grants later.
	if e.Policy.RBAC() {
		if checker, ok := e.Backend.(interface {
			Authorize(context.Context, api.Action) error
		}); ok {
			for _, action := range p.Spec.Actions {
				if err = checker.Authorize(ctx, action); err != nil {
					return e.fail(ctx, t, p, "PermissionDenied", err.Error())
				}
			}
		}
	}
	if p.Status.ApprovalUID == "" {
		p.Status.ApprovalUID = string(approval.Object.GetUID())
		now := e.now()
		p.Status.ExecutionStartedAt = &now
		p.Status.Phase = "Executing"
		if err = e.Backend.SavePlanStatus(ctx, p); err != nil {
			return err
		}
	}
	t.Status.Phase = "Executing"
	if err = e.Backend.SaveTaskStatus(ctx, t); err != nil {
		return err
	}
	for _, action := range p.Spec.Actions {
		var entry *api.JournalEntry
		for n := range p.Status.Entries {
			if p.Status.Entries[n].ID == action.ID {
				entry = &p.Status.Entries[n]
				break
			}
		}
		if entry != nil && (entry.State == "Applied" || entry.State == "Verified") {
			continue
		}
		// Fresh state is required before every action, including after process interruption.
		freshTask, getErr := e.Backend.GetTask(ctx, namespace, name)
		if getErr != nil {
			return getErr
		}
		t = freshTask
		u, err = e.Backend.Get(ctx, action.Target)
		if apierrors.IsNotFound(err) {
			u = nil
		} else if err != nil {
			return err
		}
		if err = ValidateApprovalSet(ctx, e.Backend, t, p, approval, e.Policy, e.now()); err != nil {
			return e.fail(ctx, t, p, "AuthorizationChanged", err.Error())
		}
		bindings, bindingErr := api.ResolveBindings(p.Spec)
		if bindingErr != nil {
			return bindingErr
		}
		if deletionPending(p, bindings[action.BindingID], u) {
			t.Status.Report = "Waiting for approved deletion to complete before creating the replacement."
			return e.Backend.SaveTaskStatus(ctx, t)
		}
		acquired, err = e.claimAll(ctx, namespace, p)
		if err != nil || !acquired {
			return err
		}
		if entry != nil {
			if action.Type == "DeleteResource" && u != nil && u.GetDeletionTimestamp() != nil && string(u.GetUID()) == action.Target.UID {
				currentDigest, _ := api.DigestTarget(u)
				if entry.State == "Pending" && currentDigest == entry.BeforeDigest {
					t.Status.Report = "Waiting for approved deletion to complete."
					return e.Backend.SaveTaskStatus(ctx, t)
				}
			}
			digest, _ := ResultDigest(u, action)
			if digest == entry.AfterDigest && (u == nil || u.GetAnnotations()[api.OperationAnnotation] == entry.Operation) {
				entry.State = "Applied"
				entry.UpdatedAt = e.now()
				if u != nil {
					entry.ResultUID = string(u.GetUID())
					entry.ServerResultDigest, _ = ObservedResultDigest(u, action)
				}
				if err = e.Backend.SavePlanStatus(ctx, p); err != nil {
					return err
				}
				continue
			}
		}
		if err = policy.AuthorizeAction(action, u, e.Policy); err != nil {
			return e.fail(ctx, t, p, "PolicyDenied", err.Error())
		}
		desired, buildErr := PrepareResult(p, action, u)
		if buildErr != nil {
			return e.fail(ctx, t, p, "InvalidAction", buildErr.Error())
		}
		if err = fillSecret(ctx, e.Backend, action, desired); err != nil {
			return e.fail(ctx, t, p, "InvalidAction", err.Error())
		}
		before := "absent"
		if u != nil {
			before, _ = api.DigestTarget(u)
		}
		after, _ := ResultDigest(desired, action)
		if entry == nil {
			p.Status.Entries = append(p.Status.Entries, api.JournalEntry{ID: action.ID, State: "Pending", Operation: Operation(p, action.ID), BeforeDigest: before, AfterDigest: after, UpdatedAt: e.now()})
			entry = &p.Status.Entries[len(p.Status.Entries)-1]
			if err = e.Backend.SavePlanStatus(ctx, p); err != nil {
				return err
			}
		} else if before != entry.BeforeDigest {
			return e.fail(ctx, t, p, "AmbiguousAction", "pending action target changed; manual inspection required")
		}
		if e.Policy.RBAC() {
			if checker, ok := e.Backend.(interface {
				Authorize(context.Context, api.Action) error
			}); ok {
				if err = checker.Authorize(ctx, action); err != nil {
					return e.fail(ctx, t, p, "PermissionDenied", err.Error())
				}
			}
		}
		dryResult, dryErr := e.Backend.Execute(ctx, action, u, desired, true)
		if dryErr != nil {
			return e.fail(ctx, t, p, "DryRunRejected", dryErr.Error())
		}
		dryDigest, _ := ResultDigest(dryResult, action)
		if dryDigest != after {
			return e.fail(ctx, t, p, "AdmissionChangedResult", "dry-run changed approved action result")
		}
		// Recheck approval lifetime/claim after dry-run; conditional writes fence later target changes.
		if err = ValidateApprovalSet(ctx, e.Backend, t, p, approval, e.Policy, e.now()); err != nil {
			return e.fail(ctx, t, p, "ApprovalExpired", err.Error())
		}
		acquired, err = e.claimAll(ctx, namespace, p)
		if err != nil || !acquired {
			return err
		}
		if e.Policy.RBAC() {
			if checker, ok := e.Backend.(interface {
				Authorize(context.Context, api.Action) error
			}); ok {
				if err = checker.Authorize(ctx, action); err != nil {
					return e.fail(ctx, t, p, "PermissionDenied", err.Error())
				}
			}
		}
		result, writeErr := e.Backend.Execute(ctx, action, u, desired, false)
		if writeErr != nil {
			return writeErr
		} // Pending journal deliberately survives ambiguous API failures.
		if action.Type == "DeleteResource" {
			remaining, readErr := ReadTarget(ctx, e.Backend, action.Target)
			if readErr != nil {
				return readErr
			}
			if remaining != nil {
				// DELETE acknowledgement is not an Applied absence. Admission
				// independently confirms the journal only after the object is gone.
				t.Status.Report = "Waiting for approved deletion to complete."
				return e.Backend.SaveTaskStatus(ctx, t)
			}
		}
		resultDigest, _ := ResultDigest(result, action)
		if resultDigest != after {
			return e.fail(ctx, t, p, "UnexpectedResult", "API result differed from the admitted plan")
		}
		entry.State = "Applied"
		entry.UpdatedAt = e.now()
		if result != nil {
			entry.ResultUID = string(result.GetUID())
			entry.ServerResultDigest, _ = ObservedResultDigest(result, action)
		}
		if err = e.Backend.SavePlanStatus(ctx, p); err != nil {
			return err
		}
	}
	p.Status.Phase = "Verifying"
	t.Status.Phase = "Verifying"
	if err = e.Backend.SaveTaskStatus(ctx, t); err != nil {
		return err
	}
	u, err = e.Backend.Get(ctx, p.Spec.TargetRef)
	if apierrors.IsNotFound(err) {
		u = nil
	} else if err != nil {
		return err
	}
	healthy := false
	if len(p.Spec.Checks) > 0 {
		checker := e.Checker
		checker.Reader = e.Backend
		checker.Pods = e.Backend
		if t.Spec.Scope != nil {
			checker.Scope = *t.Spec.Scope
		} else {
			checker.Scope = api.Scope{Namespaces: []string{p.Spec.TargetRef.Namespace}}
		}
		results, checkErr := checker.EvaluateChecks(ctx, p.Spec.Checks)
		if checkErr != nil {
			return e.fail(ctx, t, p, "Inconclusive", checkErr.Error())
		}
		p.Status.CheckResults = results
		healthy = ChecksHealthy(results)
		fingerprint := ChecksFingerprint(results)
		if p.Status.VerificationFingerprint != fingerprint {
			p.Status.StableSince = nil
			p.Status.VerificationFingerprint = fingerprint
		}
	} else {
		legacyHealthy, resourceFingerprint, checkErr := CheckResource(u, p.Spec.Verification)
		if p.Spec.Verification.Type == "PodRecovery" && p.Status.VerificationFingerprint != resourceFingerprint {
			p.Status.StableSince = nil
			p.Status.VerificationFingerprint = resourceFingerprint
		}
		if checkErr != nil {
			return e.fail(ctx, t, p, "Inconclusive", checkErr.Error())
		}
		legacyHealthy = legacyHealthy && CheckHealth(ctx, p.Spec.Verification.HealthURL)
		if p.Spec.Verification.Type == "DeploymentRecovery" {
			podsHealthy, fingerprint, podErr := CheckPods(ctx, e.Backend, u)
			if podErr != nil {
				return podErr
			}
			legacyHealthy = legacyHealthy && podsHealthy
			if p.Status.VerificationFingerprint != fingerprint {
				p.Status.StableSince = nil
				p.Status.VerificationFingerprint = fingerprint
			}
		}
		healthy = legacyHealthy
	}
	now := e.now()
	if !healthy {
		p.Status.StableSince = nil
	} else if p.Status.StableSince == nil {
		p.Status.StableSince = &now
	}
	if p.Status.StableSince != nil && now.Sub(*p.Status.StableSince) >= time.Duration(p.Spec.Verification.StableWindowSeconds)*time.Second {
		p.Status.Phase = "Succeeded"
		for n := range p.Status.Entries {
			p.Status.Entries[n].State = "Verified"
		}
		t.Status.Phase = "Succeeded"
		t.Status.CompletedAt = &now
		t.Status.Conditions = api.AppendConditions(t.Status.Conditions, api.Condition{Type: "RemediationVerified", Status: "True", Reason: "OriginalFailureResolved", Message: "Approved action and stable recovery verified", ObservedGeneration: t.Object.GetGeneration(), LastTransitionTime: now})
		p.Status.Conditions = api.AppendConditions(p.Status.Conditions, t.Status.Conditions[len(t.Status.Conditions)-1])
		if err = e.Backend.SavePlanStatus(ctx, p); err != nil {
			return err
		}
		// The durable plan is terminal; release before a competing monitor status
		// update can make task projection fail and hide the old plan reference.
		if err = e.releaseAll(ctx, namespace, p); err != nil {
			return err
		}
		return e.Backend.SaveTaskStatus(ctx, t)
	}
	if p.Status.ExecutionStartedAt != nil && now.Sub(*p.Status.ExecutionStartedAt) > time.Duration(p.Spec.Verification.TimeoutSeconds)*time.Second {
		return e.fail(ctx, t, p, "VerificationTimedOut", "API action completed but original failure did not resolve in time")
	}
	return e.Backend.SavePlanStatus(ctx, p)
}
func (e *Executor) fail(ctx context.Context, t *kube.Task, p *kube.Plan, reason, message string) error {
	now := e.now()
	message = evidence.Bound(evidence.Redact(message), 4096)
	p.Status.Phase = "Failed"
	t.Status.Phase = "Failed"
	t.Status.Report = message
	t.Status.CompletedAt = &now
	t.Status.Conditions = api.AppendConditions(t.Status.Conditions, api.Condition{Type: "RemediationVerified", Status: "False", Reason: reason, Message: message, ObservedGeneration: t.Object.GetGeneration(), LastTransitionTime: now})
	p.Status.Conditions = api.AppendConditions(p.Status.Conditions, t.Status.Conditions[len(t.Status.Conditions)-1])
	if err := e.Backend.SavePlanStatus(ctx, p); err != nil {
		return err
	}
	if err := e.releaseAll(ctx, p.Object.GetNamespace(), p); err != nil {
		return err
	}
	return e.Backend.SaveTaskStatus(ctx, t)
}
