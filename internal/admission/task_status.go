package admission

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func (v *Validator) taskStatus(ctx context.Context, r *admissionv1.AdmissionRequest, u *unstructured.Unstructured) error {
	oldObject, err := object(r.OldObject.Raw)
	if err != nil {
		return err
	}
	old, err := kube.ParseTask(oldObject)
	if err != nil {
		return err
	}
	next, err := kube.ParseTask(u)
	if err != nil {
		return err
	}
	if r.UserInfo.Username == v.ExecutorUser {
		before := old.Status
		after := next.Status
		// Executor owns execution outcome, never investigation authorization epochs.
		before.Phase = ""
		after.Phase = ""
		before.Report = ""
		after.Report = ""
		before.CompletedAt = nil
		after.CompletedAt = nil
		before.Conditions = nil
		after.Conditions = nil
		a, _ := api.Hash(before)
		b, _ := api.Hash(after)
		if a != b {
			return fmt.Errorf("executor cannot change investigation/cycle/plan ownership")
		}
		if (old.Status.Phase == "Succeeded" || old.Status.Phase == "Failed" || old.Status.Phase == "Rejected") && next.Status.Phase != old.Status.Phase {
			return fmt.Errorf("executor cannot reopen terminal task")
		}
		return nil
	}
	if old.Status.ObservedGeneration == next.Status.ObservedGeneration && (next.Status.Cycle < old.Status.Cycle || next.Status.Cycle > old.Status.Cycle+1) {
		return fmt.Errorf("monitoring cycles are monotonic")
	}
	// Admission JSON maps contain float64 numbers; use the API-stored generation.
	current, err := v.Backend.GetTask(ctx, r.Namespace, r.Name)
	if err != nil {
		return err
	}
	if current.Object.GetUID() != u.GetUID() {
		return fmt.Errorf("task identity changed")
	}
	if next.Status.ObservedGeneration < old.Status.ObservedGeneration || next.Status.ObservedGeneration != current.Object.GetGeneration() {
		return fmt.Errorf("investigation generation differs from task intent")
	}
	if next.Status.Incident != nil {
		digest, _ := api.Hash(next.Status.Incident.OriginalChecks)
		if digest != next.Status.Incident.OriginalChecksDigest {
			return fmt.Errorf("original check digest must match actual checks")
		}
		if len(current.Spec.Checks) > 0 {
			expected, _ := api.Hash(current.Spec.Checks)
			if digest != expected {
				return fmt.Errorf("incident changed owner checks")
			}
		}
	}
	if old.Status.Incident != nil && next.Status.Incident != nil && old.Status.ObservedGeneration == next.Status.ObservedGeneration && old.Status.Incident.Target.UID == next.Status.Incident.Target.UID && old.Status.Incident.OriginalChecksDigest != next.Status.Incident.OriginalChecksDigest {
		return fmt.Errorf("same-resource incident cannot weaken original checks by changing ID")
	}
	if old.Status.Incident != nil && next.Status.Incident != nil && old.Status.Incident.ID == next.Status.Incident.ID {
		a, _ := api.Hash(old.Status.Incident.OriginalChecks)
		b, _ := api.Hash(next.Status.Incident.OriginalChecks)
		if a != b || next.Status.Incident.OriginalChecksDigest != old.Status.Incident.OriginalChecksDigest {
			return fmt.Errorf("incident checks are immutable")
		}
	}
	if next.Status.PlanRef != nil {
		p, err := v.Backend.GetPlan(ctx, r.Namespace, next.Status.PlanRef.Name)
		if err != nil {
			return err
		}
		if next.Status.PlanRef.UID != string(p.Object.GetUID()) || p.Spec.TaskRef.UID != string(u.GetUID()) || p.Spec.TaskGeneration != current.Object.GetGeneration() || p.Spec.TaskCycle != next.Status.Cycle {
			return fmt.Errorf("current plan must bind exact task generation and cycle")
		}
	}
	return nil
}
