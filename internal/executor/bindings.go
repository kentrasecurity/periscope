package executor

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sort"
	"time"
)

type TargetReader interface {
	Get(context.Context, api.TargetRef) (*unstructured.Unstructured, error)
}

func Bindings(p *kube.Plan) ([]api.TargetBinding, error) {
	m, err := api.ResolveBindings(p.Spec)
	if err != nil {
		return nil, err
	}
	out := make([]api.TargetBinding, 0, len(m))
	for _, b := range m {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := api.ResourceKey(out[i].Target), api.ResourceKey(out[j].Target)
		if a == b {
			return out[i].ID < out[j].ID
		}
		return a < b
	})
	return out, nil
}
func ReadTarget(ctx context.Context, r TargetReader, t api.TargetRef) (*unstructured.Unstructured, error) {
	u, err := r.Get(ctx, t)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	return u, err
}
func ValidateApprovalSet(ctx context.Context, r TargetReader, t *kube.Task, p *kube.Plan, a *kube.Approval, c policy.Config, now time.Time) error {
	primary, err := ReadTarget(ctx, r, p.Spec.TargetRef)
	if err != nil {
		return err
	}
	if err = ValidateApproval(t, p, a, primary, c, now); err != nil {
		return err
	}
	if len(p.Spec.Targets) == 0 {
		return nil
	}
	bindings, err := Bindings(p)
	if err != nil {
		return err
	}
	for _, b := range bindings {
		// Future absence is only enabled by a confirmed delete journal, never initially assumed.
		if b.AfterActionID != "" {
			confirmed := false
			for _, j := range p.Status.Entries {
				if j.ID == b.AfterActionID && (j.State == "Applied" || j.State == "Verified") && j.AfterDigest == "absent" {
					confirmed = true
				}
			}
			if !confirmed {
				continue
			}
		}
		current, err := ReadTarget(ctx, r, b.Target)
		if err != nil {
			return err
		}
		if deletionPending(p, b, current) {
			continue // The acknowledged old incarnation is still terminating; no create is authorized yet.
		}
		if current != nil && t.Spec.Scope != nil && !t.Spec.Scope.Matches(b.Target, current) {
			return fmt.Errorf("bound target no longer matches scope")
		}
		digest := "absent"
		if current != nil {
			digest, _ = api.DigestTarget(current)
		}
		allowed := digest == b.Preconditions.SpecDigest && (current == nil && b.Target.UID == "" || current != nil && string(current.GetUID()) == b.Target.UID)
		if p.Status.ApprovalUID == string(a.Object.GetUID()) {
			for _, action := range p.Spec.Actions {
				if api.ResourceKey(action.Target) != api.ResourceKey(b.Target) {
					continue
				}
				for _, j := range p.Status.Entries {
					if j.ID != action.ID || (j.State != "Pending" && j.State != "Applied" && j.State != "Verified") {
						continue
					}
					after, _ := ResultDigest(current, action)
					if j.AfterDigest == after && creationUnchanged(current, action, j) && (current == nil || current.GetAnnotations()[api.OperationAnnotation] == j.Operation && (j.ResultUID == "" || j.ResultUID == string(current.GetUID())) && (action.Type == "CreateResource" || string(current.GetUID()) == action.Target.UID)) {
						allowed = true
					}
				}
			}
		}
		if !allowed {
			return fmt.Errorf("bound target %s changed outside approved history", api.ResourceKey(b.Target))
		}
	}
	return nil
}

func deletionPending(p *kube.Plan, b api.TargetBinding, current *unstructured.Unstructured) bool {
	if b.AfterActionID == "" || current == nil || current.GetDeletionTimestamp() == nil {
		return false
	}
	digest, _ := api.DigestTarget(current)
	for _, a := range p.Spec.Actions {
		if a.ID != b.AfterActionID || a.Type != "DeleteResource" || a.Target.UID != string(current.GetUID()) || api.ResourceKey(a.Target) != api.ResourceKey(b.Target) {
			continue
		}
		for _, j := range p.Status.Entries {
			if j.ID == a.ID && (j.State == "Applied" || j.State == "Verified") && j.AfterDigest == "absent" && j.BeforeDigest == digest {
				return true
			}
		}
	}
	return false
}

// ClaimKeys coordinates every served API version and incarnation of a logical resource.
func ClaimKeys(p *kube.Plan) []string {
	bindings, err := Bindings(p)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, b := range bindings {
		key := api.ClaimKey(b.Target)
		if !seen[key] {
			out = append(out, key)
			seen[key] = true
		}
	}
	sort.Strings(out)
	return out
}
func ClaimNamespace(p *kube.Plan, c policy.Config) string {
	if c.CoordinationNamespace != "" {
		return c.CoordinationNamespace
	}
	return p.Object.GetNamespace()
}
func (e *Executor) claimAll(ctx context.Context, ns string, p *kube.Plan) (bool, error) {
	ns = ClaimNamespace(p, e.Policy)
	acquired := []string{}
	for _, key := range ClaimKeys(p) {
		var ok bool
		var err error
		if aware, available := e.Backend.(interface {
			ClaimPlan(context.Context, string, string, *kube.Plan) (bool, error)
		}); available {
			ok, err = aware.ClaimPlan(ctx, ns, key, p)
		} else {
			ok, err = e.Backend.Claim(ctx, ns, key, string(p.Object.GetUID()))
		}
		if err != nil || !ok {
			for _, k := range acquired {
				_ = e.Backend.Release(ctx, ns, k, string(p.Object.GetUID()))
			}
			return false, err
		}
		acquired = append(acquired, key)
	}
	return true, nil
}
func (e *Executor) releaseAll(ctx context.Context, ns string, p *kube.Plan) error {
	ns = ClaimNamespace(p, e.Policy)
	for _, key := range ClaimKeys(p) {
		if err := e.Backend.Release(ctx, ns, key, string(p.Object.GetUID())); err != nil {
			return err
		}
	}
	return nil
}

// ActionBaseline chains only earlier actions for the same exact resource.
func ActionBaseline(p *kube.Plan, index int) (string, error) {
	bindings, err := api.ResolveBindings(p.Spec)
	if err != nil {
		return "", err
	}
	a := p.Spec.Actions[index]
	b := bindings[a.BindingID]
	baseline := b.Preconditions.SpecDigest
	for n := 0; n < index; n++ {
		prior := p.Spec.Actions[n]
		confirmed := false
		for _, j := range p.Status.Entries {
			if j.ID == prior.ID && (j.State == "Applied" || j.State == "Verified") {
				confirmed = true
				if api.ResourceKey(prior.Target) == api.ResourceKey(a.Target) {
					baseline = j.AfterDigest
				}
			}
		}
		if !confirmed {
			return "", fmt.Errorf("prior action incomplete")
		}
	}
	return baseline, nil
}
