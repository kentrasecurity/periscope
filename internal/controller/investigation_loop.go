package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/observation"
	"github.com/kentrasecurity/periscope/internal/policy"
	"strings"
	"time"
)

func Investigate(ctx context.Context, t *kube.Task, r *observation.Registry, m llm.ToolClient) (llm.Decision, error) {
	return investigate(ctx, t, r, m, nil, nil, nil)
}

// symptoms re-evaluates the incident's original checks and returns the failing
// results, so the model starts from what the operator detected rather than
// re-deriving it (a one-letter selector typo is easy to read past).
func (i *Investigator) symptoms(ctx context.Context, t *kube.Task) []api.CheckResult {
	if i.Checker.Reader == nil || t.Status.Incident == nil || len(t.Status.Incident.OriginalChecks) == 0 {
		return nil
	}
	checker := i.Checker
	if t.Spec.Scope != nil {
		checker.Scope = *t.Spec.Scope
	}
	results, err := checker.EvaluateChecks(ctx, t.Status.Incident.OriginalChecks)
	if err != nil {
		return nil
	}
	failing := []api.CheckResult{}
	for _, r := range results {
		if !r.Healthy {
			failing = append(failing, r)
		}
	}
	return failing
}

func investigate(ctx context.Context, t *kube.Task, r *observation.Registry, m llm.ToolClient, symptoms []api.CheckResult, rejected []llm.RejectedAction, validate func(llm.Decision) error) (llm.Decision, error) {
	scope := api.Scope{Namespaces: []string{t.Object.GetNamespace()}}
	if t.Spec.Scope != nil {
		scope = *t.Spec.Scope
	}
	request := map[string]any{"permissionMode": "RBAC", "mode": t.Spec.Mode, "objective": t.Spec.Objective, "target": t.Spec.TargetRef, "scope": scope, "evidence": t.Status.Evidence, "incident": t.Status.Incident, "verification": t.Spec.Verification, "rejectedActions": rejected}
	if len(symptoms) > 0 {
		request["symptoms"] = symptoms
	}
	if t.Status.Incident != nil && len(t.Status.Incident.OriginalChecks) > 0 && t.Status.Incident.OriginalChecks[0].Type == "LogSignature" {
		request["applicationError"] = "Experimental: this workload is healthy by status, but its recent logs repeat the application error in symptoms. Look for a Kubernetes-side cause: a NetworkPolicy that blocks the destination or the source, a Service with wrong ports or no endpoints, a wrong DNS name or port in env or ConfigMaps, an Ingress or certificate problem. Repair that configuration with the smallest change that keeps the existing security intent (allow only the affected source and port). If the cause is inside the application or outside the cluster, return no actions and say so."
	}
	if enabled := enabledRepairs(r.Repairs, r.StorageClasses(ctx)); len(enabled) > 0 {
		request["enabledRepairs"] = enabled
	}
	if t.Spec.Mode == "Observe" {
		request["instruction"] = "Observe mode: diagnose only; nothing you propose is executed. Investigate with read tools, then call finish_plan with an empty actions array. In diagnosis state the root cause, the evidence IDs supporting it and the concrete remediation an operator should apply."
	}
	raw, _ := json.Marshal(request)
	c := llm.Conversation{Tools: r.Definitions(), Messages: []llm.Message{{Role: "user", Text: string(raw)}}}
	ids := map[string]bool{}
	lastRejection := ""
	exhausted := func(what string) error {
		if lastRejection != "" {
			// The owner needs the reason the model could not converge.
			return fmt.Errorf("%s; last rejected proposal: %s", what, lastRejection)
		}
		return errors.New(what)
	}
	for turn := 0; turn < 20; turn++ {
		if t.Status.ModelCalls >= t.Spec.Limits.MaxModelCalls {
			return llm.Decision{}, exhausted("model-call budget exhausted")
		}
		if err := reserveTask(t, 1, 0); err != nil {
			return llm.Decision{}, err
		}
		t.Status.ModelCalls++
		if r.Checkpoint != nil {
			if err := r.Checkpoint(ctx); err != nil {
				return llm.Decision{}, err
			}
		}
		result, err := m.Turn(ctx, c)
		if err != nil {
			var rejected *llm.ProposalError
			if errors.As(err, &rejected) {
				lastRejection = evidence.Bound(evidence.Redact(rejected.Reason), 512)
				c.Messages = append(c.Messages, llm.Message{Role: "assistant", Text: rejected.Proposal, ProviderItems: rejected.ProviderItems}, llm.Message{Role: "user", Text: "Planner rejected the structured proposal: " + rejected.Reason + ". Use finish_plan with only supported fields and action types, explicit targets for related resources, and the original owner checks. Correct the proposal within the original scope; never execute actions."})
				continue
			}
			return llm.Decision{}, err
		}
		if result.Decision != nil {
			if len(result.Calls) != 0 {
				return llm.Decision{}, fmt.Errorf("mixed decision/tool requests")
			}
			validationErr := validateDecisionEvidence(*result.Decision, t.Status.Evidence)
			if validationErr == nil && validate != nil {
				validationErr = validate(*result.Decision)
			}
			if validationErr != nil {
				lastRejection = evidence.Bound(evidence.Redact(validationErr.Error()), 512)
				proposal, _ := json.Marshal(result.Decision)
				c.Messages = append(c.Messages, llm.Message{Role: "assistant", Text: string(proposal)}, llm.Message{Role: "user", Text: "Planner rejected this proposal: " + evidence.Bound(evidence.Redact(validationErr.Error()), 2048) + ". Reconsider the validation failure and provide a valid executable plan inside the original task scope, retaining the original checks. If the goal cannot be repaired safely, return no actions and explain the gap."})
				continue
			}
			return *result.Decision, nil
		}
		if len(result.Calls) == 0 || len(result.Calls) > 16 {
			return llm.Decision{}, fmt.Errorf("invalid tool batch")
		}
		c.Messages = append(c.Messages, llm.Message{Role: "assistant", ToolCalls: result.Calls, ProviderItems: result.ProviderItems})
		for _, call := range result.Calls {
			if ids[call.ID] {
				return llm.Decision{}, fmt.Errorf("duplicate tool call ID")
			}
			ids[call.ID] = true
			if t.Status.ToolCalls >= t.Spec.Limits.MaxToolCalls {
				return llm.Decision{}, exhausted("tool-call budget exhausted")
			}
			if err := reserveTask(t, 0, 1); err != nil {
				return llm.Decision{}, err
			}
			t.Status.ToolCalls++
			if r.Checkpoint != nil {
				if err := r.Checkpoint(ctx); err != nil {
					return llm.Decision{}, err
				}
			}
			observed, err := r.Call(ctx, scope, call)
			if err != nil {
				observed = observation.ToolResult{CallID: call.ID, Source: call.Name, ObservedAt: time.Now().UTC(), Gap: evidence.Bound(evidence.Redact(err.Error()), 1024)}
			}
			// The model still sees results once the persisted evidence list is
			// full; it is told they cannot be cited, instead of failing the
			// whole investigation.
			recorded := len(t.Status.Evidence) < api.MaxEvidenceItems
			if !recorded {
				observed.Gap = strings.TrimPrefix(observed.Gap+"; evidence item limit reached: this result cannot be cited, cite earlier evidence IDs", "; ")
			}
			b, _ := json.Marshal(observed)
			hash, _ := api.Hash(observed)
			if recorded {
				t.Status.Evidence = append(t.Status.Evidence, api.Evidence{ID: "tool-" + call.ID, Source: observed.Source, Hash: hash, CollectedAt: observed.ObservedAt, Content: evidence.Bound(string(b), 8192)})
			}
			c.Messages = append(c.Messages, llm.Message{Role: "tool", ToolCallID: call.ID, Text: string(b)})
		}
	}
	return llm.Decision{}, fmt.Errorf("investigation turn limit exceeded")
}

func validateDecisionEvidence(d llm.Decision, observed []api.Evidence) error {
	known := make(map[string]bool, len(observed))
	ids := make([]string, 0, len(observed))
	for _, item := range observed {
		known[item.ID] = true
		ids = append(ids, item.ID)
	}
	for _, id := range d.EvidenceRefs {
		if !known[id] {
			return fmt.Errorf("model cited unavailable evidence %q; cite only available evidence IDs: %s", id, strings.Join(ids, ", "))
		}
	}
	return nil
}

// enabledRepairs describes the opt-in repairs for the model; without them it
// must report Secret and storage faults for owner action.
func enabledRepairs(r policy.Repairs, storageClasses []string) []string {
	out := []string{}
	if r.Secrets.Create != "" && r.Secrets.Create != "none" {
		line := "create a missing Opaque Secret with CreateResource: object without data or stringData, and secretSources naming each key"
		if strings.Contains(r.Secrets.Create, policy.SecretsGenerate) {
			line += `; {"generate": 16..64} fills random bytes`
		}
		if strings.Contains(r.Secrets.Create, policy.SecretsFromSource) {
			line += fmt.Sprintf(`; {"fromSecret": name, "fromKey": key} copies a key from one of %v`, r.Secrets.Sources)
		}
		out = append(out, line+"; existing Secrets are never changed. Reading Secrets is always denied to you by design: a forbidden Secret read is expected and is not a blocker; a Pod status or Event saying the Secret is not found is sufficient evidence that it is missing. Create only a Secret that a workload in scope references by name, with exactly the referenced keys")
	}
	if r.Storage.ReplaceUnboundClaims {
		line := "replace a PersistentVolumeClaim that never bound (Pending, no volumeName): DeleteResource then CreateResource with the same name"
		if len(storageClasses) > 0 {
			line += fmt.Sprintf("; the cluster's StorageClasses are %v: when the claim names a class that does not exist, use the existing class whose name is nearest to it (the evident intent), never a class chosen only because another claim uses it", storageClasses)
		}
		out = append(out, line)
	}
	if r.Storage.ExpandClaims {
		out = append(out, "increase a PersistentVolumeClaim's spec.resources.requests.storage")
	}
	return out
}
