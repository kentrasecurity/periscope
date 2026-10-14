package controller

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"time"
)

// monitor runs before planning. It never changes a workload or approves a
// human request, and yields to an active journal so recovery stays authoritative.
func (i *Investigator) monitor(ctx context.Context, t *kube.Task) (bool, error) {
	now := time.Now().UTC()
	t.Status.LastCheckedAt = &now
	ref := taskTarget(t)
	u, err := i.Collector.Reader.Get(ctx, ref)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Status.Healthy = nil
		t.Status.Report = "Monitoring cannot read target: " + err.Error()
		return true, i.Backend.SaveTaskStatus(ctx, t)
	}
	if apierrors.IsNotFound(err) {
		u = nil
	}
	var p *kube.Plan
	if t.Status.PlanRef != nil {
		p, err = i.Backend.GetPlan(ctx, t.Object.GetNamespace(), t.Status.PlanRef.Name)
		if err != nil {
			return true, err
		}
	}
	verification := api.Verification{Type: "DeploymentRecovery", TimeoutSeconds: 300, StableWindowSeconds: 120, HealthURL: i.Policy.HealthURL(ref)}
	known := ref.Kind == "Deployment" || ref.Kind == "Pod"
	switch ref.Kind {
	case "StatefulSet", "DaemonSet", "ReplicaSet", "Service", "PersistentVolumeClaim", "Job":
		verification.Type, verification.HealthURL = "ResourceHealthy", ""
		known = true
	}
	if t.Spec.Scope != nil && t.Status.MonitorVerification != nil {
		verification = *t.Status.MonitorVerification
		known = true
	}
	if ref.Kind == "Pod" {
		verification.Type = "PodRecovery"
	}
	if t.Spec.Verification != nil {
		verification = *t.Spec.Verification
		verification.HealthURL = i.Policy.HealthURL(ref)
		known = true
	} else if p != nil {
		verification = p.Spec.Verification
		known = true
	}
	if !known && t.Status.MonitorVerification != nil {
		verification = *t.Status.MonitorVerification
		known = true
	}
	if t.Status.Incident != nil {
		for _, check := range t.Status.Incident.OriginalChecks {
			if check.StableWindowSeconds > verification.StableWindowSeconds {
				verification.StableWindowSeconds = check.StableWindowSeconds
			}
			if check.TimeoutSeconds > verification.TimeoutSeconds {
				verification.TimeoutSeconds = check.TimeoutSeconds
			}
		}
	}
	if known {
		copy := verification
		t.Status.MonitorVerification = &copy
	}
	healthy := false
	fingerprint := ""
	var checkErr error
	if known {
		healthy, fingerprint, checkErr = executor.CheckResource(u, verification)
	}
	if healthy && verification.Type == "DeploymentRecovery" {
		healthy, fingerprint, checkErr = executor.CheckPods(ctx, i.Collector.Reader, u)
	}
	if healthy && verification.Type == "ResourceHealthy" && u != nil && u.GetKind() == "Service" {
		healthy, fingerprint, checkErr = executor.CheckService(ctx, i.Collector.Reader, u)
	}
	if healthy {
		healthy = executor.CheckHealth(ctx, verification.HealthURL)
	}
	if checkErr != nil {
		healthy = false
	}
	if t.Status.Incident != nil && len(t.Status.Incident.OriginalChecks) > 0 || len(t.Spec.Checks) > 0 {
		checks := t.Spec.Checks
		if t.Status.Incident != nil {
			checks = t.Status.Incident.OriginalChecks
		}
		checker := i.Checker
		checker.Reader = i.Collector.Reader
		checker.Pods = i.Collector.Reader
		if t.Spec.Scope != nil {
			checker.Scope = *t.Spec.Scope
		} else {
			checker.Scope = api.Scope{Namespaces: []string{ref.Namespace}}
		}
		results, e := checker.EvaluateChecks(ctx, checks)
		if e != nil {
			return true, e
		}
		healthy = executor.ChecksHealthy(results)
		fingerprint = executor.ChecksFingerprint(results)
	}
	previousHealthy := t.Status.Healthy != nil && *t.Status.Healthy
	previousDigest, previousUID := t.Status.MonitorDigest, t.Status.MonitorUID
	digest, uid := "absent", ""
	if u != nil {
		digest, _ = api.DigestTarget(u)
		uid = string(u.GetUID())
	}
	t.Status.MonitorDigest = digest
	t.Status.MonitorUID = uid
	t.Status.Healthy = &healthy
	active := p != nil && (p.Status.Phase == "Executing" || p.Status.Phase == "Verifying" || p.Status.ApprovalUID != "" && p.Status.Phase != "Succeeded" && p.Status.Phase != "Failed")
	if active {
		return true, i.Backend.SaveTaskStatus(ctx, t)
	}
	if healthy {
		if t.Spec.Scope == nil {
			t.Status.Suspects = nil // scoped suspects belong to other resources
		}
		if t.Status.MonitorStableSince == nil || t.Status.MonitorFingerprint != fingerprint || previousUID != uid {
			t.Status.MonitorStableSince = &now
		}
		t.Status.MonitorFingerprint = fingerprint
		if t.Status.PlanRef != nil {
			t.Status.Cycle++
		}
		t.Status.ApprovalRef = nil
		t.Status.PlanRef = nil // a resolved failure cannot later consume its pending approval
		if t.Status.Phase != "Succeeded" {
			t.Status.Phase = "Monitoring"
			t.Status.Report = "Target currently satisfies health checks; monitoring stability."
		}
		if now.Sub(*t.Status.MonitorStableSince) >= time.Duration(verification.StableWindowSeconds)*time.Second {
			if t.Status.Incident != nil {
				t.Status.IncidentHistory = append(t.Status.IncidentHistory, *t.Status.Incident)
				if len(t.Status.IncidentHistory) > 64 {
					t.Status.IncidentHistory = t.Status.IncidentHistory[len(t.Status.IncidentHistory)-64:]
				}
				t.Status.Incident = nil
			}

			t.Status.Phase = "Succeeded"
			t.Status.CompletedAt = &now
			t.Status.Report = "Target satisfies the verification contract; monitoring continues."
		}
		return true, i.Backend.SaveTaskStatus(ctx, t)
	}
	t.Status.MonitorStableSince = nil
	t.Status.MonitorFingerprint = ""
	if t.Spec.Scope != nil && t.Status.Incident != nil && t.Status.Incident.Attempt >= api.TaskHealingLimits(t.Spec).MaxAttemptsPerIncident && (p == nil || p.Status.Phase == "Failed") {
		t.Status.IncidentHistory = append(t.Status.IncidentHistory, *t.Status.Incident)
		if len(t.Status.IncidentHistory) > 64 {
			t.Status.IncidentHistory = t.Status.IncidentHistory[len(t.Status.IncidentHistory)-64:]
		}
		t.Status.Incident = nil
		t.Status.PlanRef = nil
		t.Status.ApprovalRef = nil
		t.Status.Cycle++
		t.Status.Phase = "Monitoring"
		t.Status.Report = "Incident attempts exhausted; monitoring other scoped resources continues."
		return true, i.Backend.SaveTaskStatus(ctx, t)
	}
	changed := previousDigest != "" && (previousDigest != digest || previousUID != uid)
	if p != nil && p.Spec.PolicyDigest != policy.PolicyDigest(i.Policy) {
		changed = true
	}
	if p != nil && p.Status.Phase == "" && p.Spec.Preconditions.SpecDigest == digest && p.Spec.TargetRef.UID == uid && p.Spec.PolicyDigest == policy.PolicyDigest(i.Policy) {
		if err = i.Backend.SaveTaskStatus(ctx, t); err != nil {
			return true, err
		}
		return true, i.requestApproval(ctx, t, p)
	}
	retry, nextAttempt, _ := RetryDecision(t, p, now)
	if p == nil && t.Status.Phase == "Blocked" && t.Status.Incident != nil && t.Status.Incident.NextAttemptAt != nil && !now.Before(*t.Status.Incident.NextAttemptAt) && t.Status.Incident.Attempt < api.TaskHealingLimits(t.Spec).MaxAttemptsPerIncident {
		retry = true
	}
	if t.Status.Incident != nil && !nextAttempt.IsZero() {
		t.Status.Incident.NextAttemptAt = &nextAttempt
	}
	if p != nil && p.Status.Phase == "Failed" && !(previousUID != "" && previousUID != uid) && !retry {
		return true, i.Backend.SaveTaskStatus(ctx, t)
	}
	if t.Status.Incident != nil && t.Status.Incident.Attempt >= api.TaskHealingLimits(t.Spec).MaxAttemptsPerIncident && !(previousUID != "" && previousUID != uid) {
		return true, i.Backend.SaveTaskStatus(ctx, t)
	}
	if (t.Status.Phase == "Blocked" || t.Status.Phase == "Failed") && !changed && !retry {
		return true, i.Backend.SaveTaskStatus(ctx, t)
	}
	if previousHealthy || changed || p != nil || retry {
		if previousUID != "" && previousUID != uid {
			t.Status.Incident = nil
		}
		if p != nil && t.Status.Incident != nil {
			t.Status.Incident.PriorPlanRefs = append(t.Status.Incident.PriorPlanRefs, api.ObjectRef{Name: p.Object.GetName(), UID: string(p.Object.GetUID())})
			t.Status.Incident.Attempt++
		}
		if retry && p == nil && t.Status.Incident != nil {
			t.Status.Incident.Attempt++
			t.Status.Incident.NextAttemptAt = nil
		}
		if t.Status.Incident != nil { // a new attempt; an earlier hold no longer applies
			t.Status.Incident.Outcome = ""
			t.Status.Incident.Diagnosis = ""
		}
		t.Status.Cycle++
		t.Status.ApprovalRef = nil
		t.Status.PlanRef = nil
		t.Status.Phase = "Pending"
		if t.Spec.Scope != nil || t.Spec.HealingLimits != nil {
			t.Status.ModelCalls = 0
			t.Status.ToolCalls = 0
		}
		t.Status.StartedAt = nil
		t.Status.CompletedAt = nil
		if err = i.Backend.SaveTaskStatus(ctx, t); err != nil {
			return true, err
		}
	}
	// A fresh failure of a single target waits out the grace period after the
	// cycle bookkeeping above; scoped incidents were debounced during discovery.
	if !retry && t.Status.Incident == nil && t.Status.PlanRef == nil && t.Spec.Scope == nil {
		target := ref
		target.UID = uid
		if inGracePeriod(t, target, now) {
			t.Status.Phase = "Monitoring"
			t.Status.Report = graceReport(t, 1)
			return true, i.Backend.SaveTaskStatus(ctx, t)
		}
	}
	return false, nil
}
