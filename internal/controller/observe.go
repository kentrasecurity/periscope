package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/observation"
	"strings"
	"time"
)

// observe is the RBAC-mode Observe loop: periodic health checks without model
// calls while healthy, one read-only model diagnosis per new failure, and no
// plans, approvals or writes. A diagnosed failure is not diagnosed again until
// its failure signature changes or it recovers and relapses.
func (i *Investigator) observe(ctx context.Context, t *kube.Task) error {
	now := time.Now().UTC()
	if t.Status.Phase != "Pending" && t.Status.LastCheckedAt != nil && now.Sub(*t.Status.LastCheckedAt) < observeInterval(t) {
		return nil
	}
	findings, gaps, covered, err := i.observeFindings(ctx, t)
	if err != nil {
		return err
	}
	findings, waiting := debounce(t, findings, covered, now)
	t.Status.LastCheckedAt = &now
	t.Status.Gaps = boundGaps(gaps)
	healthy := len(findings) == 0
	t.Status.PlanRef = nil
	t.Status.ApprovalRef = nil
	if healthy {
		if t.Status.Healthy != nil && !*t.Status.Healthy {
			t.Status.Cycle++ // a relapse after recovery is a new incident and is diagnosed again
		}
		archiveIncident(t)
		t.Status.Healthy = &healthy
		t.Status.PendingIncidents = nil
		t.Status.Phase = "Monitoring"
		t.Status.Report = "No unhealthy resources observed."
		if waiting > 0 {
			t.Status.Report = graceReport(t, waiting)
		}
		if len(gaps) > 0 {
			t.Status.Report += " Some resources could not be assessed; see gaps."
		}
		t.Status.Conditions = []api.Condition{{Type: "Healthy", Status: "True", Reason: "NoUnhealthyResources", Message: t.Status.Report, ObservedGeneration: t.Object.GetGeneration(), LastTransitionTime: now}}
		return i.Backend.SaveTaskStatus(ctx, t)
	}
	incidents := make([]api.IncidentStatus, 0, len(findings))
	next := -1
	for _, f := range findings {
		incident := newIncident(t, f)
		if known := diagnosedIncident(t, incident, now); known != nil {
			incident = *known
		} else if next < 0 {
			next = len(incidents)
		}
		incidents = append(incidents, incident)
	}
	t.Status.Healthy = &healthy
	t.Status.Phase = "Degraded"
	t.Status.Conditions = []api.Condition{{Type: "Healthy", Status: "False", Reason: "UnhealthyResources", Message: fmt.Sprintf("%d unhealthy resource(s) observed", len(findings)), ObservedGeneration: t.Object.GetGeneration(), LastTransitionTime: now}}
	if t.Status.Incident != nil && !containsIncident(incidents, t.Status.Incident.ID) {
		archiveIncident(t) // recovered, or its failure changed into a new incident
	}
	note := ""
	if next >= 0 {
		if t.Status.Incident == nil || t.Status.Incident.ID != incidents[next].ID {
			archiveIncident(t)
			t.Status.Incident = &incidents[next]
			t.Status.ModelCalls, t.Status.ToolCalls = 0, 0
		}
		note = i.diagnose(ctx, t)
		incidents[next] = *t.Status.Incident
	}
	t.Status.PendingIncidents = nil
	for n, incident := range incidents {
		if n != next && len(t.Status.PendingIncidents) < 100 && (t.Status.Incident == nil || incident.ID != t.Status.Incident.ID) {
			t.Status.PendingIncidents = append(t.Status.PendingIncidents, incident)
		}
	}
	t.Status.Report = observedReport(incidents)
	if note != "" {
		t.Status.Report += "\n" + note
	}
	t.Status.Report = evidence.Bound(t.Status.Report, 16384)
	return i.Backend.SaveTaskStatus(ctx, t)
}

func containsIncident(incidents []api.IncidentStatus, id string) bool {
	for _, incident := range incidents {
		if incident.ID == id {
			return true
		}
	}
	return false
}

func observeInterval(t *kube.Task) time.Duration {
	if t.Spec.Monitoring != nil {
		return time.Duration(t.Spec.Monitoring.IntervalSeconds) * time.Second
	}
	return 30 * time.Second
}

// observeFindings returns unhealthy resources for a scope or a single target.
func (i *Investigator) observeFindings(ctx context.Context, t *kube.Task) ([]Finding, []string, coverage, error) {
	if t.Spec.Scope != nil {
		findings, gaps, covered, err := i.scanScope(ctx, t)
		if err != nil {
			return nil, nil, coverage{}, err
		}
		findings, err = i.recheckKnown(ctx, t, findings)
		return findings, gaps, covered, err
	}
	findings, gaps, err := i.observeTarget(ctx, t)
	return findings, gaps, coverage{all: err == nil}, err
}

// observeTarget checks a single-target task's resource.
func (i *Investigator) observeTarget(ctx context.Context, t *kube.Task) ([]Finding, []string, error) {
	ref := resolvedTaskSpec(t).TargetRef
	if !i.Policy.ReadAllowed(ref) {
		return nil, []string{"target is not enrolled for investigation"}, nil
	}
	u, err := executor.ReadTarget(ctx, i.Collector.Reader, ref)
	if err != nil {
		return nil, []string{"target read unavailable: " + evidence.Bound(evidence.Redact(err.Error()), 512)}, nil
	}
	if u != nil {
		ref.UID = string(u.GetUID())
	}
	if len(t.Spec.Checks) > 0 {
		checker := i.Checker
		checker.Reader = i.Collector.Reader
		checker.Pods = i.Collector.Reader
		checker.Scope = api.Scope{Namespaces: []string{ref.Namespace}}
		results, err := checker.EvaluateChecks(ctx, t.Spec.Checks)
		if err != nil || executor.ChecksHealthy(results) {
			return nil, nil, err
		}
		return []Finding{{Target: ref, Checks: t.Spec.Checks, FailureFingerprint: executor.ChecksFingerprint(results)}}, nil, nil
	}
	v := api.Verification{Type: "ResourceHealthy", TimeoutSeconds: 180, StableWindowSeconds: 10}
	switch {
	case t.Spec.Verification != nil:
		v = *t.Spec.Verification
	case ref.Kind == "Pod":
		v.Type = "PodRecovery"
	case ref.Kind == "Deployment":
		v = api.Verification{Type: "DeploymentRecovery", TimeoutSeconds: 300, StableWindowSeconds: 120}
	}
	v.HealthURL = i.Policy.HealthURL(ref)
	checker := i.Checker
	checker.Reader = i.Collector.Reader
	checker.Pods = i.Collector.Reader
	checker.Scope = api.Scope{Namespaces: []string{ref.Namespace}}
	check := api.VerificationCheck(ref, v)
	results, err := checker.EvaluateChecks(ctx, []api.Check{check})
	if err != nil {
		return nil, nil, err
	}
	if executor.ChecksHealthy(results) {
		return nil, nil, nil
	}
	if u != nil && strings.HasPrefix(results[0].Observation, "no supported observed health condition") {
		return nil, []string{ref.Kind + ": explicit goal checks required for unknown health semantics"}, nil
	}
	fingerprint, _ := api.Hash([]any{ref, executor.FailureSignature(u)})
	return []Finding{{Target: ref, Checks: []api.Check{check}, FailureFingerprint: fingerprint}}, nil, nil
}

// recheckKnown re-evaluates already known incidents with their own checks.
// Bounded discovery may not reach every kind in one pass, so absence from a
// scan is not evidence of recovery.
func (i *Investigator) recheckKnown(ctx context.Context, t *kube.Task, findings []Finding) ([]Finding, error) {
	scanned := map[string]bool{}
	for _, f := range findings {
		scanned[f.Target.UID] = true
	}
	known := append([]api.IncidentStatus{}, t.Status.PendingIncidents...)
	if t.Status.Incident != nil {
		known = append(known, *t.Status.Incident)
	}
	checker := i.Checker
	checker.Reader = i.Collector.Reader
	checker.Pods = i.Collector.Reader
	checker.Scope = *t.Spec.Scope
	for _, incident := range known {
		if scanned[incident.Target.UID] || len(incident.OriginalChecks) == 0 {
			continue
		}
		scanned[incident.Target.UID] = true
		results, err := checker.EvaluateChecks(ctx, incident.OriginalChecks)
		if err != nil {
			return nil, err
		}
		current, err := executor.ReadTarget(ctx, i.Collector.Reader, incident.Target)
		if err != nil {
			return nil, err
		}
		if !executor.ChecksHealthy(results) && current != nil && string(current.GetUID()) == incident.Target.UID {
			findings = append(findings, Finding{Target: incident.Target, Checks: incident.OriginalChecks, FailureFingerprint: incident.FailureFingerprint})
		}
	}
	return findings, nil
}

func newIncident(t *kube.Task, f Finding) api.IncidentStatus {
	digest, _ := api.Hash(f.Checks)
	id, _ := api.Hash([]any{string(t.Object.GetUID()), t.Object.GetGeneration(), t.Status.Cycle, f.Target.UID, digest, f.FailureFingerprint})
	return api.IncidentStatus{ID: id, Target: f.Target, Attempt: 1, OriginalChecks: f.Checks, OriginalChecksDigest: digest, FailureFingerprint: f.FailureFingerprint}
}

// diagnosedIncident returns the recorded incident when the same failure was
// already diagnosed, or is cooling down after an unavailable diagnosis.
func diagnosedIncident(t *kube.Task, incident api.IncidentStatus, now time.Time) *api.IncidentStatus {
	candidates := append([]api.IncidentStatus{}, t.Status.IncidentHistory...)
	if t.Status.Incident != nil {
		candidates = append(candidates, *t.Status.Incident)
	}
	for n := len(candidates) - 1; n >= 0; n-- {
		c := candidates[n]
		if c.ID != incident.ID {
			continue
		}
		if c.Diagnosis != "" || c.NextAttemptAt != nil && now.Before(*c.NextAttemptAt) {
			return &c
		}
		return nil
	}
	return nil
}

func archiveIncident(t *kube.Task) {
	if t.Status.Incident == nil {
		return
	}
	t.Status.IncidentHistory = append(t.Status.IncidentHistory, *t.Status.Incident)
	if len(t.Status.IncidentHistory) > 64 {
		t.Status.IncidentHistory = t.Status.IncidentHistory[len(t.Status.IncidentHistory)-64:]
	}
	t.Status.Incident = nil
}

// diagnose collects bounded evidence and asks the model for a read-only
// explanation. Failures leave the incident undiagnosed with a retry cooldown
// and return a note for the report.
func (i *Investigator) diagnose(ctx context.Context, t *kube.Task) string {
	incident := t.Status.Incident
	retryLater := func(reason string) string {
		next := time.Now().UTC().Add(time.Duration(api.TaskHealingLimits(t.Spec).RetryCooldownSeconds) * time.Second)
		incident.NextAttemptAt = &next
		incident.Diagnosis = ""
		return reason
	}
	if renewWindow(t); t.Status.Budget.ModelCalls >= api.TaskHealingLimits(t.Spec).MaxModelCallsPerWindow {
		return retryLater("Diagnosis deferred: rolling model budget exhausted; health checks continue.")
	}
	collector := i.Collector
	collector.Scope = t.Spec.Scope
	collector.MaxToolCalls = min(t.Spec.Limits.MaxToolCalls, 100)
	collector.Reader = budgetReader{Reader: i.Collector.Reader, t: t, save: i.Backend.SaveTaskStatus}
	b, err := collector.Collect(ctx, incident.Target, incident.Target.Namespace)
	t.Status.Evidence = b.Evidence
	if err != nil {
		return retryLater("Diagnosis deferred: evidence unavailable: " + evidence.Bound(evidence.Redact(err.Error()), 1024))
	}
	model, ok := i.Model.(llm.ToolClient)
	if !ok {
		incident.Diagnosis = "No tool-capable model is configured; review the collected evidence."
		return ""
	}
	registry := observation.NewRegistry(i.Collector.Reader, i.Policy, max(t.Spec.Limits.MaxToolCalls-t.Status.ToolCalls, 1))
	if i.ConfigureTools != nil {
		i.ConfigureTools(registry)
	}
	registry.Checkpoint = func(ctx context.Context) error { return i.Backend.SaveTaskStatus(ctx, t) }
	d, err := investigate(ctx, t, registry, model, i.symptoms(ctx, t), nil, nil)
	if err != nil {
		return retryLater("Diagnosis unavailable: " + evidence.Bound(evidence.Redact(err.Error()), 1024))
	}
	incident.Diagnosis = evidence.Bound(evidence.Redact(diagnosisText(d)), 2048)
	incident.NextAttemptAt = nil
	return ""
}

// diagnosisText appends model-suggested actions as text; Observe never executes them.
func diagnosisText(d llm.Decision) string {
	text := strings.TrimSpace(d.Diagnosis)
	if len(d.Actions) == 0 {
		return text
	}
	suggested := []string{}
	for _, a := range d.Actions {
		raw, _ := json.Marshal(map[string]any{"type": a.Type, "target": a.Target, "patch": a.Patch})
		suggested = append(suggested, string(raw))
	}
	return text + "\nSuggested actions (not executed): " + strings.Join(suggested, "; ")
}

func observedReport(incidents []api.IncidentStatus) string {
	lines := []string{fmt.Sprintf("%d unhealthy resource(s) observed; Observe mode never changes resources.", len(incidents))}
	for _, incident := range incidents {
		diagnosis := incident.Diagnosis
		if diagnosis == "" {
			diagnosis = "diagnosis pending"
		}
		lines = append(lines, fmt.Sprintf("- %s/%s/%s: %s", incident.Target.Namespace, incident.Target.Kind, incident.Target.Name, diagnosis))
	}
	return strings.Join(lines, "\n")
}
