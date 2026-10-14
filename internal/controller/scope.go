package controller

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"strings"
	"time"
)

func taskTarget(t *kube.Task) api.TargetRef {
	if t.Spec.Scope != nil && t.Status.Incident != nil {
		return t.Status.Incident.Target
	}
	ref := t.Spec.TargetRef
	if ref.Namespace == "" {
		ref.Namespace = t.Object.GetNamespace()
	}
	return ref
}

// prepareScope keeps the user spec intact and selects one incident at a time.
func (i *Investigator) prepareScope(ctx context.Context, t *kube.Task) (bool, error) {
	now := time.Now().UTC()
	failure := lastFailure(t)
	// A repair failure a new investigation cannot address must not stall the
	// other incidents in scope: hold it for the owner and move on.
	unretryable := t.Status.Phase == "Failed" && failure != nil && !retryableFailure(failure.Reason)
	if t.Status.Incident != nil && (t.Status.Phase == "Blocked" || t.Status.Phase == "Rejected" || unretryable || t.Status.Phase == "Failed" && t.Status.Incident.Attempt >= api.TaskHealingLimits(t.Spec).MaxAttemptsPerIncident) {
		held := *t.Status.Incident
		if unretryable && held.Outcome == "" {
			held.Outcome = api.IncidentRepairFailed
			held.Diagnosis = evidence.Bound(evidence.Redact("Repair failed ("+failure.Reason+"): "+failure.Message), 2048)
		}
		if held.Attempt < api.TaskHealingLimits(t.Spec).MaxAttemptsPerIncident {
			next := now.Add(time.Duration(api.TaskHealingLimits(t.Spec).RetryCooldownSeconds) * time.Second)
			if t.Status.ModelCalls >= t.Spec.Limits.MaxModelCalls || t.Status.Budget.ModelCalls >= api.TaskHealingLimits(t.Spec).MaxModelCallsPerWindow || t.Status.Budget.ToolCalls >= api.TaskHealingLimits(t.Spec).MaxToolCallsPerWindow {
				next = t.Status.Budget.WindowStartedAt.Add(time.Duration(api.TaskHealingLimits(t.Spec).WindowSeconds) * time.Second)
			}
			if !next.After(now) {
				next = now.Add(time.Duration(api.TaskHealingLimits(t.Spec).RetryCooldownSeconds) * time.Second)
			}
			held.NextAttemptAt = &next
		}
		t.Status.IncidentHistory = append(t.Status.IncidentHistory, held)
		if len(t.Status.IncidentHistory) > 64 {
			t.Status.IncidentHistory = t.Status.IncidentHistory[len(t.Status.IncidentHistory)-64:]
		}
		t.Status.Incident = nil
		t.Status.PlanRef = nil
		t.Status.ApprovalRef = nil
		t.Status.Cycle++
		t.Status.StartedAt = nil
	}
	active := t.Status.Incident != nil
	interval := 30
	if t.Spec.Monitoring != nil {
		interval = t.Spec.Monitoring.IntervalSeconds
	}
	if active && t.Status.LastScopeScanAt != nil && now.Sub(*t.Status.LastScopeScanAt) < time.Duration(interval)*time.Second {
		return false, nil
	}
	t.Status.LastScopeScanAt = &now
	t.Status.LastCheckedAt = &now
	findings, gaps, covered, err := i.scanScope(ctx, t)
	if err != nil {
		return true, err
	}
	findings, waiting := debounce(t, findings, covered, now)
	eligible := findings[:0]
	exhausted := 0
	needsOwner, retrying := []string{}, []string{}
	for _, finding := range findings {
		var held *api.IncidentStatus
		digest, _ := api.Hash(finding.Checks)
		for n, prior := range t.Status.IncidentHistory {
			if prior.Target.UID == finding.Target.UID && prior.OriginalChecksDigest == digest && prior.FailureFingerprint == finding.FailureFingerprint && (prior.Outcome != "" || prior.Attempt >= api.TaskHealingLimits(t.Spec).MaxAttemptsPerIncident || prior.NextAttemptAt != nil && now.Before(*prior.NextAttemptAt)) {
				held = &t.Status.IncidentHistory[n]
				break
			}
		}
		switch {
		case held != nil && held.Outcome != "":
			exhausted++
			gaps = append(gaps, "owner action needed ("+held.Outcome+"): "+api.ResourceKey(finding.Target))
			needsOwner = append(needsOwner, fmt.Sprintf("- %s: %s", api.ResourceKey(finding.Target), held.Diagnosis))
		case held != nil && held.Attempt >= api.TaskHealingLimits(t.Spec).MaxAttemptsPerIncident:
			exhausted++
			gaps = append(gaps, "incident attempts exhausted: "+api.ResourceKey(finding.Target))
			needsOwner = append(needsOwner, fmt.Sprintf("- %s: repair attempts exhausted", api.ResourceKey(finding.Target)))
		case held != nil:
			// A cooldown or exhausted model budget: retried automatically.
			retrying = append(retrying, fmt.Sprintf("- %s: retry after %s", api.ResourceKey(finding.Target), held.NextAttemptAt.Format(time.RFC3339)))
		default:
			eligible = append(eligible, finding)
		}
	}
	findings = eligible
	t.Status.Gaps = boundGaps(gaps)
	t.Status.PendingIncidents = nil
	for index, f := range findings {
		digest, _ := api.Hash(f.Checks)
		id, _ := api.Hash([]any{string(t.Object.GetUID()), t.Object.GetGeneration(), t.Status.Cycle, f.Target.UID})
		incident := api.IncidentStatus{ID: id, Target: f.Target, Attempt: 1, OriginalChecks: f.Checks, OriginalChecksDigest: digest, FailureFingerprint: f.FailureFingerprint}
		for n := len(t.Status.IncidentHistory) - 1; n >= 0; n-- {
			prior := t.Status.IncidentHistory[n]
			if prior.Target.UID == f.Target.UID && prior.FailureFingerprint == f.FailureFingerprint && prior.OriginalChecksDigest == digest {
				incident = prior
				incident.Attempt++
				incident.NextAttemptAt = nil
				break
			}
		}
		if active {
			if f.Target.UID != t.Status.Incident.Target.UID && len(t.Status.PendingIncidents) < 100 {
				t.Status.PendingIncidents = append(t.Status.PendingIncidents, incident)
			}
			continue
		}
		if index == 0 {
			t.Status.Incident = &incident
			t.Status.ModelCalls = 0
			t.Status.ToolCalls = 0
			c := f.Checks[0]
			t.Status.MonitorVerification = &api.Verification{Type: c.Type, Path: c.Path, Expected: c.Expected, TimeoutSeconds: c.TimeoutSeconds, StableWindowSeconds: c.StableWindowSeconds}
			if c.Type == "DNS" || c.Type == "TCP" || c.Type == "HTTP" || c.Type == "Prometheus" || c.Type == "LogSignature" {
				// Plans verify workloads with their complete verifier; the
				// original checks still decide recovery.
				switch {
				case f.Target.Kind == "Pod":
					t.Status.MonitorVerification.Type = "PodRecovery"
				case f.Target.Kind == "Deployment" && f.Target.APIVersion == "apps/v1":
					t.Status.MonitorVerification.Type = "DeploymentRecovery"
				default:
					t.Status.MonitorVerification.Type = "ResourceHealthy"
				}
			}
			for _, check := range f.Checks {
				if check.TimeoutSeconds > t.Status.MonitorVerification.TimeoutSeconds {
					t.Status.MonitorVerification.TimeoutSeconds = check.TimeoutSeconds
				}
				if check.StableWindowSeconds > t.Status.MonitorVerification.StableWindowSeconds {
					t.Status.MonitorVerification.StableWindowSeconds = check.StableWindowSeconds
				}
			}
			t.Status.PlanRef = nil
			t.Status.ApprovalRef = nil
			t.Status.Phase = "Pending"
			t.Status.StartedAt = nil
			t.Status.CompletedAt = nil
			t.Status.MonitorDigest = ""
			t.Status.MonitorUID = ""
		} else if len(t.Status.PendingIncidents) < 100 {
			t.Status.PendingIncidents = append(t.Status.PendingIncidents, incident)
		}
	}
	if len(findings) == 0 && !active {
		// Coverage gaps (unknown health semantics, unreadable kinds) are reported
		// separately; they do not make an otherwise healthy scope unhealthy.
		healthy := exhausted == 0 && len(retrying) == 0
		t.Status.Healthy = &healthy
		t.Status.Phase = "Monitoring"
		switch {
		case exhausted > 0 || len(retrying) > 0:
			lines := []string{}
			if exhausted > 0 {
				lines = append(lines, fmt.Sprintf("%d unhealthy resource(s) need owner action (no safe repair, failed repair, or attempts exhausted); see incidentHistory and gaps.", exhausted))
				lines = append(lines, needsOwner...)
			}
			if len(retrying) > 0 {
				lines = append(lines, fmt.Sprintf("%d unhealthy resource(s) wait to be retried (cooldown or model budget):", len(retrying)))
				lines = append(lines, retrying...)
			}
			t.Status.Report = evidence.Bound(strings.Join(lines, "\n"), 16384)
		case waiting > 0:
			t.Status.Report = graceReport(t, waiting)
		case len(gaps) > 0:
			t.Status.Report = "Periodic scope check complete; no observed unhealthy resources. Some resources could not be assessed; see gaps."
		default:
			t.Status.Report = "Periodic scope check complete; no observed unhealthy resources."
		}
	}
	return len(findings) == 0 && !active, i.Backend.SaveTaskStatus(ctx, t)
}

func resolvedTaskSpec(t *kube.Task) api.TaskSpec {
	s := t.Spec
	if s.Scope == nil && s.TargetRef.Namespace == "" {
		s.TargetRef.Namespace = t.Object.GetNamespace()
	}
	return s
}

func boundGaps(gaps []string) []string {
	if len(gaps) > 32 {
		gaps = append(append([]string{}, gaps[:31]...), "additional coverage gaps omitted")
	}
	return gaps
}

// scanScope evaluates the owner's explicit checks, or otherwise discovers
// unhealthy resources inside the scope. It never calls the model.
func (i *Investigator) scanScope(ctx context.Context, t *kube.Task) ([]Finding, []string, coverage, error) {
	if len(t.Spec.Checks) == 0 {
		findings, gaps, covered, err := i.discoverIncidents(ctx, *t.Spec.Scope, &t.Status.ScopeScanCursor)
		if err == nil {
			appFindings, appGaps := i.applicationErrors(ctx, *t.Spec.Scope, findings)
			findings, gaps = append(findings, appFindings...), append(gaps, appGaps...)
		}
		return findings, gaps, covered, err
	}
	checker := i.Checker
	checker.Reader = i.Collector.Reader
	checker.Pods = i.Collector.Reader
	checker.Scope = *t.Spec.Scope
	results, err := checker.EvaluateChecks(ctx, t.Spec.Checks)
	if err != nil || executor.ChecksHealthy(results) {
		return nil, nil, coverage{all: err == nil}, err
	}
	ref := t.Spec.Checks[0].Target
	u, err := executor.ReadTarget(ctx, i.Collector.Reader, ref)
	if err != nil {
		return nil, nil, coverage{}, err
	}
	if u != nil {
		ref.UID = string(u.GetUID())
	}
	return []Finding{{Target: ref, Checks: t.Spec.Checks, FailureFingerprint: executor.ChecksFingerprint(results)}}, nil, coverage{all: true}, nil
}
