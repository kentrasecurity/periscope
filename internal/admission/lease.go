package admission

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"time"
)

// Claims coordinate approved plans; they never grant workload authority.
func (v *Validator) lease(ctx context.Context, r *admissionv1.AdmissionRequest) error {
	if r.Operation != admissionv1.Create && r.Operation != admissionv1.Update {
		return fmt.Errorf("claim operation forbidden")
	}
	next, err := object(r.Object.Raw)
	if err != nil {
		return err
	}
	holder, _, _ := unstructured.NestedString(next.Object, "spec", "holderIdentity")
	duration, _, _ := unstructured.NestedFloat64(next.Object, "spec", "leaseDurationSeconds")
	if duration != 120 || next.GetName() != r.Name || next.GetNamespace() != r.Namespace {
		return fmt.Errorf("invalid claim identity or duration")
	}
	release := holder == ""
	if r.Operation == admissionv1.Update {
		old, e := object(r.OldObject.Raw)
		if e != nil {
			return e
		}
		prior, _, _ := unstructured.NestedString(old.Object, "spec", "holderIdentity")
		if !release && prior != "" && prior != holder {
			stamp, _, _ := unstructured.NestedString(old.Object, "spec", "renewTime")
			t, e := time.Parse(time.RFC3339Nano, stamp)
			ttl, _, _ := unstructured.NestedFloat64(old.Object, "spec", "leaseDurationSeconds")
			if e != nil || ttl <= 0 || t.Add(time.Duration(ttl)*time.Second).After(time.Now()) {
				return fmt.Errorf("another plan holds a live claim")
			}
		}
	}
	if release {
		if r.Operation != admissionv1.Update {
			return fmt.Errorf("empty claim forbidden")
		}
		old, e := object(r.OldObject.Raw)
		if e != nil {
			return e
		}
		holder, _, _ = unstructured.NestedString(old.Object, "spec", "holderIdentity")
	}
	var plans []*kube.Plan
	recordNS, planName := next.GetAnnotations()["periscope.kentrasecurity.io/plan-namespace"], next.GetAnnotations()["periscope.kentrasecurity.io/plan"]
	if recordNS != "" && planName != "" {
		p, e := v.Backend.GetPlan(ctx, recordNS, planName)
		if e != nil {
			return fmt.Errorf("claim plan unavailable")
		}
		plans = []*kube.Plan{p}
	} else {
		for _, ns := range v.Policy.Namespaces {
			items, e := kube.CurrentPlans(ctx, v.Backend, ns)
			if e != nil {
				return e
			}
			plans = append(plans, items...)
		}
	}
	err = nil
	if err != nil {
		return err
	}
	for _, p := range plans {
		if string(p.Object.GetUID()) != holder || r.Namespace != executor.ClaimNamespace(p, v.Policy) {
			continue
		}
		matched := false
		for _, key := range executor.ClaimKeys(p) {
			if r.Name == kube.ClaimName(key) {
				matched = true
			}
		}
		if !matched {
			continue
		}
		if release {
			return nil
		}
		task, e := v.Backend.GetTask(ctx, p.Object.GetNamespace(), p.Spec.TaskRef.Name)
		if e != nil {
			continue
		}
		approvals, e := kube.CurrentApprovals(ctx, v.Backend, p)
		if e != nil {
			continue
		}
		for _, a := range approvals {
			if executor.ValidateApprovalSet(ctx, v.Backend, task, p, a, v.Policy, time.Now().UTC()) == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("claim requires a current approved plan")
}
