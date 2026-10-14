package controller

import (
	"context"
	"fmt"

	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/policy"
)

func rejectedActions(p *kube.Plan) []llm.RejectedAction {
	if p.Status.Phase != "Failed" {
		return nil
	}
	var failure *api.Condition
	for n := range p.Status.Conditions {
		c := &p.Status.Conditions[n]
		if c.Reason == "DryRunRejected" || c.Reason == "PermissionDenied" {
			failure = c
		}
	}
	if failure == nil {
		return nil
	}
	out := []llm.RejectedAction{}
	for _, a := range p.Spec.Actions {
		before := ""
		for _, j := range p.Status.Entries {
			if j.ID == a.ID && j.State == "Pending" {
				before = j.BeforeDigest
			}
		}
		// Older single-action plans may not contain a journal entry yet.
		if before == "" && len(p.Spec.Actions) == 1 {
			before = p.Spec.Preconditions.SpecDigest
		}
		if before != "" {
			out = append(out, llm.RejectedAction{PlanName: p.Object.GetName(), Action: a, BeforeDigest: before, Reason: failure.Reason, Message: evidence.Bound(evidence.Redact(failure.Message), 4096)})
		}
	}
	return out
}

// Compare results, not action IDs: a new name does not make a rejected write valid.
// A changed baseline is new evidence and can legitimately change API validity.
func rejectRepeatedActions(ctx context.Context, r executor.TargetReader, primary api.TargetRef, d llm.Decision, rejected []llm.RejectedAction) error {
	for _, a := range d.Actions {
		if a.Type != "PatchResource" {
			continue
		}
		if a.Target.Name == "" {
			a.Target = primary
		}
		if a.Target.Namespace == "" {
			a.Target.Namespace = primary.Namespace
		}
		for _, old := range rejected {
			if old.Action.Type != a.Type || api.ResourceKey(old.Action.Target) != api.ResourceKey(a.Target) {
				continue
			}
			current, err := executor.ReadTarget(ctx, r, a.Target)
			if err != nil {
				return err
			}
			if current == nil {
				continue
			}
			before, _ := api.DigestTarget(current)
			if before != old.BeforeDigest {
				continue
			}
			proposed, err := policy.BuildResult(a, current)
			if err != nil {
				continue
			}
			previous, err := policy.BuildResult(old.Action, current)
			if err != nil {
				continue
			}
			left, _ := api.DigestTarget(proposed)
			right, _ := api.DigestTarget(previous)
			if left == right {
				return fmt.Errorf("%s: equivalent action already rejected on unchanged target by plan %s: %s", old.Reason, old.PlanName, old.Message)
			}
		}
	}
	return nil
}
