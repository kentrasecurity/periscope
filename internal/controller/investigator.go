package controller

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/observation"
	"github.com/kentrasecurity/periscope/internal/policy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"strings"
	"time"
)

type Investigator struct {
	Checker        executor.CheckEvaluator
	ConfigureTools func(*observation.Registry)
	Backend        kube.InvestigatorBackend
	Model          llm.Client
	Policy         policy.Config
	Collector      evidence.Collector
}

func PlanName(t *kube.Task) string {
	h, _ := api.Hash([]any{string(t.Object.GetUID()), t.Object.GetGeneration(), t.Status.Cycle})
	name := t.Object.GetName()
	if len(name) > 30 {
		name = name[:30]
	}
	return fmt.Sprintf("%s-g%d-%s", strings.TrimRight(name, "-"), t.Object.GetGeneration(), h[7:19])
}

func (i *Investigator) Reconcile(ctx context.Context, namespace, name string) error {
	t, e := i.Backend.GetTask(ctx, namespace, name)
	if apierrors.IsNotFound(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if t.Spec.Suspend {
		return nil
	}
	if t.Spec.Scope != nil && t.Status.Phase == "Monitoring" && t.Status.Incident == nil && t.Status.LastCheckedAt != nil && t.Status.ObservedGeneration == t.Object.GetGeneration() {
		interval := 30
		if t.Spec.Monitoring != nil {
			interval = t.Spec.Monitoring.IntervalSeconds
		}
		if time.Since(*t.Status.LastCheckedAt) < time.Duration(interval)*time.Second {
			return nil
		}
	}
	if t.Status.ObservedGeneration == t.Object.GetGeneration() {
		if !i.Policy.RBAC() {
			switch t.Status.Phase {
			case "AwaitingApproval", "Proposed", "Executing", "Verifying", "Succeeded", "Failed", "Blocked", "Cancelled":
				return nil
			}
		}
	} else {
		t.Status = api.TaskStatus{ObservedGeneration: t.Object.GetGeneration(), Phase: "Pending", Attempt: 1}
	}
	if e = api.ValidateTask(resolvedTaskSpec(t)); e != nil {
		return i.block(ctx, t, "InvalidTask", e.Error())
	}
	renewed := renewWindow(t)
	if renewed && t.Status.Phase == "Blocked" && t.Status.Incident != nil && t.Status.Incident.Attempt < api.TaskHealingLimits(t.Spec).MaxAttemptsPerIncident {
		for _, condition := range t.Status.Conditions {
			if condition.Reason == "BudgetExceeded" && (t.Status.Incident.NextAttemptAt == nil || !time.Now().Before(*t.Status.Incident.NextAttemptAt)) {
				t.Status.Phase = "Pending"
				t.Status.StartedAt = nil
			}
		}
	}
	if i.Policy.RBAC() && t.Spec.Mode == "Observe" {
		return i.observe(ctx, t)
	}
	if t.Spec.Scope != nil {
		done, err := i.prepareScope(ctx, t)
		if done || err != nil {
			return err
		}
	}
	resolvedTarget := taskTarget(t)
	if i.Policy.RBAC() && t.Spec.Mode == "Observe" && t.Status.Phase == "Succeeded" {
		now := time.Now().UTC()
		t.Status.LastCheckedAt = &now
		u, err := i.Collector.Reader.Get(ctx, resolvedTarget)
		if err != nil {
			t.Status.Report = "Observation monitoring cannot read target: " + err.Error()
		} else {
			t.Status.TargetUID = string(u.GetUID())
			t.Status.Report = "Observation refreshed; no remediation executed."
		}
		return i.Backend.SaveTaskStatus(ctx, t)
	}
	if i.Policy.RBAC() && t.Spec.Mode != "Observe" {
		handled, err := i.monitor(ctx, t)
		if err != nil || handled {
			return err
		}
	}
	if !i.Policy.ReadAllowed(resolvedTarget) {
		return i.block(ctx, t, "ScopeDenied", "target is not enrolled for investigation")
	}
	if t.Status.StartedAt == nil {
		now := time.Now().UTC()
		t.Status.StartedAt = &now
	}
	deadline := t.Status.StartedAt.Add(time.Duration(t.Spec.Limits.DeadlineSeconds) * time.Second)
	if !time.Now().Before(deadline) {
		return i.block(ctx, t, "DeadlineExceeded", "task deadline exceeded")
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	planName := PlanName(t)
	if existing, err := i.Backend.GetPlan(ctx, namespace, planName); err == nil {
		digest, dErr := api.DigestPlan(existing.Spec)
		if existing.Spec.TaskRef.UID != string(t.Object.GetUID()) || existing.Spec.TaskGeneration != t.Object.GetGeneration() || dErr != nil || digest != existing.Spec.Digest {
			return i.block(ctx, t, "PlanConflict", "existing plan does not match task authorization")
		}
		return i.ready(ctx, t, existing)
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	if t.Status.ModelCalls >= t.Spec.Limits.MaxModelCalls || t.Status.ToolCalls >= t.Spec.Limits.MaxToolCalls {
		return i.block(ctx, t, "BudgetExceeded", "investigation budget exhausted")
	}
	t.Status.Phase = "Collecting"
	if e = i.Backend.SaveTaskStatus(ctx, t); e != nil {
		return e
	}
	collector := i.Collector
	collector.Scope = t.Spec.Scope
	collector.MaxToolCalls = t.Spec.Limits.MaxToolCalls - t.Status.ToolCalls
	rolling := t.Spec.Scope != nil || t.Spec.HealingLimits != nil
	if rolling {
		collector.Reader = budgetReader{Reader: collector.Reader, t: t, save: i.Backend.SaveTaskStatus}
	}
	b, e := collector.Collect(ctx, resolvedTarget, resolvedTarget.Namespace)
	var rejected []llm.RejectedAction
	if t.Status.Incident != nil {
		for _, ref := range t.Status.Incident.PriorPlanRefs {
			if prior, err := i.Backend.GetPlan(ctx, namespace, ref.Name); err == nil {
				if prior.Spec.TaskRef.UID == string(t.Object.GetUID()) && (ref.UID == "" || ref.UID == string(prior.Object.GetUID())) {
					for _, failure := range rejectedActions(prior) {
						if t.Spec.Scope != nil && t.Spec.Scope.Contains(failure.Action.Target) || t.Spec.Scope == nil && api.ResourceKey(failure.Action.Target) == api.ResourceKey(resolvedTarget) {
							rejected = append(rejected, failure)
						}
					}
				}
				raw, _ := api.Hash(prior.Status)
				b.Evidence = append(b.Evidence, api.Evidence{ID: "prior-" + ref.Name, Source: "prior-repair:" + ref.Name, Hash: raw, CollectedAt: time.Now().UTC(), Content: evidence.Bound(evidence.Redact(fmt.Sprintf("Prior actions: %v; outcome: %s; failures: %v", prior.Spec.Actions, prior.Status.Phase, prior.Status.Conditions)), 8192)})
			}
		}
	}
	if !rolling {
		t.Status.ToolCalls += b.ToolCalls
	}
	t.Status.Evidence = b.Evidence
	t.Status.Gaps = boundGaps(b.Gaps)
	if e != nil {
		return i.block(ctx, t, "EvidenceUnavailable", e.Error())
	}
	t.Status.TargetUID = string(b.Target.GetUID())
	if t.Spec.Mode == "Observe" {
		now := time.Now().UTC()
		t.Status.Phase = "Succeeded"
		t.Status.CompletedAt = &now
		t.Status.Report = "Observation complete; no remediation executed."
		t.Status.Conditions = []api.Condition{{Type: "InvestigationComplete", Status: "True", Reason: "Observed", Message: t.Status.Report, ObservedGeneration: t.Object.GetGeneration(), LastTransitionTime: now}}
		return i.Backend.SaveTaskStatus(ctx, t)
	}
	if i.Model == nil {
		return i.block(ctx, t, "ProviderUnavailable", "model is not configured")
	}
	if i.Policy.RBAC() && t.Status.Incident == nil && (t.Status.MonitorVerification != nil || len(t.Spec.Checks) > 0) {
		target := resolvedTarget
		target.UID = string(b.Target.GetUID())
		checks := t.Spec.Checks
		if len(checks) == 0 {
			checks = []api.Check{api.VerificationCheck(target, *t.Status.MonitorVerification)}
		}
		digest, _ := api.Hash(checks)
		id, _ := api.Hash([]any{string(t.Object.GetUID()), t.Object.GetGeneration(), t.Status.Cycle})
		t.Status.Incident = &api.IncidentStatus{ID: id, Target: target, Attempt: 1, OriginalChecks: checks, OriginalChecksDigest: digest}
	}
	t.Status.Phase = "Analyzing"
	if _, hasTools := i.Model.(llm.ToolClient); !hasTools || !i.Policy.RBAC() {
		if e := reserveTask(t, 1, 0); e != nil {
			return i.block(ctx, t, "BudgetExceeded", e.Error())
		}
		t.Status.ModelCalls++
	}
	if e = i.Backend.SaveTaskStatus(ctx, t); e != nil {
		return e
	}
	target := resolvedTarget
	target.UID = string(b.Target.GetUID())
	var capabilities []policy.Capability
	for _, cap := range i.Policy.Capabilities {
		if cap.APIVersion == target.APIVersion && cap.Kind == target.Kind && cap.Namespace == resolvedTarget.Namespace {
			for _, n := range cap.Names {
				if n == target.Name {
					capabilities = append(capabilities, cap)
					break
				}
			}
		}
	}
	if i.Policy.RBAC() {
		capabilities = []policy.Capability{{APIVersion: target.APIVersion, Kind: target.Kind, Namespace: resolvedTarget.Namespace, Names: []string{target.Name}, Types: []string{"PatchResource", "RestartWorkload", "CreateResource", "DeleteResource"}, RequireApproval: t.Spec.Mode != "Automatic", Risk: "disruptive", HealthURL: i.Policy.HealthURL(target)}}
	}
	baseline, e := api.DigestTarget(b.Target)
	if e != nil {
		return e
	}
	if b.Absent {
		baseline = "absent"
	}
	var d llm.Decision
	if model, ok := i.Model.(llm.ToolClient); ok && i.Policy.RBAC() {
		registry := observation.NewRegistry(i.Collector.Reader, i.Policy, t.Spec.Limits.MaxToolCalls-t.Status.ToolCalls)
		if i.ConfigureTools != nil {
			i.ConfigureTools(registry)
		}
		registry.Checkpoint = func(ctx context.Context) error { return i.Backend.SaveTaskStatus(ctx, t) }
		d, e = investigate(ctx, t, registry, model, i.symptoms(ctx, t), rejected, func(candidate llm.Decision) error {
			if err := rejectRepeatedActions(ctx, i.Collector.Reader, target, candidate, rejected); err != nil {
				return err
			}
			// Binding is read-only, but normalizes action targets in place. Validate
			// a copy so correction cannot contaminate the model's next proposal.
			actions := append([]api.Action(nil), candidate.Actions...)
			_, err := i.bindActions(ctx, t, target, baseline, actions)
			return err
		})
		b.Evidence = t.Status.Evidence
	} else {
		d, e = i.Model.Propose(ctx, llm.Request{Authorization: i.Policy.Authorization, Objective: t.Spec.Objective, Evidence: b, Capabilities: capabilities, RejectedActions: rejected})
		if e == nil {
			e = rejectRepeatedActions(ctx, i.Collector.Reader, target, d, rejected)
		}
	}
	if e != nil {
		return i.block(ctx, t, "ModelFailed", e.Error())
	}
	if len(d.Actions) == 0 {
		// Repeating the investigation cannot change its answer; hold the
		// incident with the reason until its failure changes.
		if t.Status.Incident != nil {
			t.Status.Incident.Diagnosis = evidence.Bound(evidence.Redact(d.Diagnosis), 2048)
			t.Status.Incident.Outcome = api.IncidentNoSafeAction
		}
		return i.block(ctx, t, "NoSafeAction", "No safe repair; owner action needed. "+d.Diagnosis)
	}
	ids := map[string]bool{}
	for _, item := range b.Evidence {
		ids[item.ID] = true
	}
	for _, id := range d.EvidenceRefs {
		if !ids[id] {
			return i.block(ctx, t, "InvalidEvidenceReference", "model cited unavailable evidence")
		}
	}
	bindings, e := i.bindActions(ctx, t, target, baseline, d.Actions)
	if e != nil {
		return i.block(ctx, t, "InvalidAction", e.Error())
	}
	if t.Status.MonitorVerification != nil {
		d.Verification = *t.Status.MonitorVerification
	}
	if t.Spec.Verification != nil {
		d.Verification = *t.Spec.Verification
		d.Verification.HealthURL = i.Policy.HealthURL(target)
	}
	if i.Policy.RBAC() && t.Status.Incident == nil {
		checks := []api.Check{api.VerificationCheck(target, d.Verification)}
		if len(t.Spec.Checks) > 0 {
			checks = t.Spec.Checks
		}
		digest, _ := api.Hash(checks)
		incidentID, _ := api.Hash([]any{string(t.Object.GetUID()), t.Object.GetGeneration(), t.Status.Cycle})
		t.Status.Incident = &api.IncidentStatus{ID: incidentID, Target: target, Attempt: 1, OriginalChecks: checks, OriginalChecksDigest: digest}
		v := d.Verification
		t.Status.MonitorVerification = &v
		if err := i.Backend.SaveTaskStatus(ctx, t); err != nil {
			return err
		}
	}
	p := api.PlanSpec{Targets: bindings, TaskCycle: t.Status.Cycle, TaskRef: api.ObjectRef{Name: t.Object.GetName(), UID: string(t.Object.GetUID())}, TaskGeneration: t.Object.GetGeneration(), TargetRef: target, Preconditions: api.Preconditions{SpecDigest: baseline}, PolicyDigest: policy.PolicyDigest(i.Policy), Diagnosis: d.Diagnosis, Risk: "low", Actions: d.Actions, Verification: d.Verification, Evidence: b.Evidence}
	if t.Status.Incident != nil {
		p.IncidentID = t.Status.Incident.ID
		p.OriginalChecksDigest = t.Status.Incident.OriginalChecksDigest
		p.Checks = t.Status.Incident.OriginalChecks
		for _, check := range p.Checks {
			if check.TimeoutSeconds > p.Verification.TimeoutSeconds {
				p.Verification.TimeoutSeconds = check.TimeoutSeconds
			}
			if check.StableWindowSeconds > p.Verification.StableWindowSeconds {
				p.Verification.StableWindowSeconds = check.StableWindowSeconds
			}
		}
	}
	for _, a := range d.Actions {
		cap, _ := i.Policy.Find(a)
		if cap.Risk != "low" {
			p.Risk = "disruptive"
		}
	}
	if e = policy.ValidatePlan(resolvedTaskSpec(t), p, i.Policy); e != nil {
		return i.block(ctx, t, "InvalidPlan", e.Error())
	}
	p.Digest, e = api.DigestPlan(p)
	if e != nil {
		return e
	}
	created, e := i.Backend.CreatePlan(ctx, namespace, planName, p)
	if apierrors.IsAlreadyExists(e) {
		created, e = i.Backend.GetPlan(ctx, namespace, planName)
	}
	if e != nil {
		return e
	}
	if created.Spec.Digest != p.Digest {
		return i.block(ctx, t, "PlanConflict", "concurrent investigation produced a different plan")
	}
	return i.ready(ctx, t, created)
}

func (i *Investigator) ready(ctx context.Context, t *kube.Task, p *kube.Plan) error {
	t.Status.PlanRef = &api.ObjectRef{Name: p.Object.GetName(), UID: string(p.Object.GetUID())}
	t.Status.Phase = "AwaitingApproval"
	if t.Spec.Mode == "Automatic" {
		t.Status.Phase = "Planned"
	}
	if t.Spec.Mode == "Propose" {
		t.Status.Phase = "Proposed"
	}
	t.Status.Report = evidence.Bound(evidence.Redact(p.Spec.Diagnosis), 16384)
	t.Status.Conditions = []api.Condition{{Type: "InvestigationComplete", Status: "True", Reason: "PlanReady", Message: "Immutable action plan ready for review", ObservedGeneration: t.Object.GetGeneration(), LastTransitionTime: time.Now().UTC()}}
	if err := i.Backend.SaveTaskStatus(ctx, t); err != nil {
		return err
	}
	return i.requestApproval(ctx, t, p)
}
func (i *Investigator) block(ctx context.Context, t *kube.Task, reason, message string) error {
	t.Status.Phase = "Blocked"
	if t.Status.Incident != nil && (reason == "ModelFailed" || reason == "EvidenceUnavailable") {
		// Kept with the incident: the report is replaced by the next scan.
		t.Status.Incident.Diagnosis = evidence.Bound(evidence.Redact(reason+": "+message), 2048)
		next := time.Now().UTC().Add(time.Duration(api.TaskHealingLimits(t.Spec).RetryCooldownSeconds) * time.Second)
		t.Status.Incident.NextAttemptAt = &next
	}
	t.Status.Report = evidence.Bound(evidence.Redact(message), 4096)
	t.Status.Conditions = []api.Condition{{Type: "Ready", Status: "False", Reason: reason, Message: t.Status.Report, ObservedGeneration: t.Object.GetGeneration(), LastTransitionTime: time.Now().UTC()}}
	return i.Backend.SaveTaskStatus(ctx, t)
}
