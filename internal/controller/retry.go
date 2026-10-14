package controller

import (
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"time"
)

func RetryDecision(t *kube.Task, p *kube.Plan, now time.Time) (bool, time.Time, string) {
	if p == nil || p.Status.Phase != "Failed" {
		return false, time.Time{}, "no terminal failure"
	}
	if t.Status.Incident != nil && t.Status.Incident.Attempt >= api.TaskHealingLimits(t.Spec).MaxAttemptsPerIncident {
		return false, time.Time{}, "incident attempt budget exhausted"
	}
	retryable := false
	stamp := time.Time{}
	for _, c := range p.Status.Conditions {
		if c.Type == "RemediationVerified" || c.Reason == "VerificationTimedOut" {
			retryable = retryableFailure(c.Reason)
			stamp = c.LastTransitionTime
		}
	}
	if !retryable {
		return false, time.Time{}, "failure requires new evidence or owner action"
	}
	next := stamp.Add(time.Duration(api.TaskHealingLimits(t.Spec).RetryCooldownSeconds) * time.Second)
	return !stamp.IsZero() && !now.Before(next), next, "remaining recovery failure"
}

// retryableFailure reports whether a new attempt can address a failed repair:
// the API rejected the write (dry run or RBAC, fed back to the model as a
// rejected action), recovery was not observed in time, or the attempt ran out
// of time or authorization without saying the repair was wrong.
func retryableFailure(reason string) bool {
	switch reason {
	case "VerificationTimedOut", "DryRunRejected", "PermissionDenied", "Inconclusive", "ApprovalExpired", "DeadlineExceeded", "AuthorizationUnavailable", "AuthorizationChanged":
		return true
	}
	return false
}

// lastFailure returns the task's latest failed remediation condition, if any.
func lastFailure(t *kube.Task) *api.Condition {
	for n := len(t.Status.Conditions) - 1; n >= 0; n-- {
		if c := t.Status.Conditions[n]; c.Type == "RemediationVerified" {
			if c.Status == "False" {
				return &t.Status.Conditions[n]
			}
			return nil
		}
	}
	return nil
}
