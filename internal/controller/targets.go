package controller

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func (i *Investigator) bindActions(ctx context.Context, t *kube.Task, primary api.TargetRef, baseline string, actions []api.Action) ([]api.TargetBinding, error) {
	composite := false
	for _, a := range actions {
		composite = composite || len(actions) > 1 && (a.Type == "CreateResource" || a.Type == "DeleteResource")
	}
	if t.Spec.Scope == nil && !composite {
		current, err := executor.ReadTarget(ctx, i.Collector.Reader, primary)
		if err != nil {
			return nil, err
		}
		for n := range actions {
			a := &actions[n]
			if a.Target.Name == "" {
				if a.Target.APIVersion != "" || a.Target.Namespace != "" || a.Target.Kind != "" || a.Target.UID != "" {
					return nil, fmt.Errorf("partial target override")
				}
				a.Target = primary
			} else {
				if a.Target.Namespace == "" {
					a.Target.Namespace = primary.Namespace
				}
				if a.Target.UID == "" {
					a.Target.UID = primary.UID
				}
			}
			if err := policy.AuthorizeAction(*a, current, i.Policy); err != nil {
				return nil, err
			}
			next, err := policy.BuildResult(*a, current)
			if err != nil {
				return nil, err
			}
			current = next
		}
		return nil, nil
	}
	bindings := []api.TargetBinding{{ID: "goal", Target: primary, Preconditions: api.Preconditions{SpecDigest: baseline}}}
	staged := map[string]*unstructured.Unstructured{}
	ids := map[string]string{api.ResourceKey(primary): "goal"}
	deleted := map[string]string{}
	for n := range actions {
		a := &actions[n]
		if a.Target.Name == "" {
			if a.Target.APIVersion != "" || a.Target.Namespace != "" || a.Target.Kind != "" || a.Target.UID != "" {
				return nil, fmt.Errorf("partial target override")
			}
			a.Target = primary
		}
		if a.Target.Namespace == "" {
			a.Target.Namespace = primary.Namespace
		}
		if t.Spec.Scope == nil && api.ResourceKey(a.Target) != api.ResourceKey(primary) {
			return nil, fmt.Errorf("related writes require an explicit owner scope")
		}
		if t.Spec.Scope != nil && !t.Spec.Scope.Contains(a.Target) {
			return nil, fmt.Errorf("write outside task scope")
		}
		key := api.ResourceKey(a.Target)
		current, loaded := staged[key]
		if !loaded {
			var err error
			current, err = executor.ReadTarget(ctx, i.Collector.Reader, a.Target)
			if err != nil && a.Type == "CreateResource" && a.Target.APIVersion == "v1" && a.Target.Kind == "Secret" && apierrors.IsForbidden(err) {
				// The investigator never reads Secrets. Absence is enforced by the
				// executor's create, which the API rejects if the Secret exists.
				current, err = nil, nil
			}
			if err != nil {
				return nil, err
			}
			staged[key] = current
		}
		if current != nil {
			if t.Spec.Scope != nil && !t.Spec.Scope.Matches(a.Target, current) {
				return nil, fmt.Errorf("write target does not match resource selector")
			}
			if a.Target.UID != "" && a.Target.UID != string(current.GetUID()) {
				return nil, fmt.Errorf("model selected stale UID")
			}
			a.Target.UID = string(current.GetUID())
		} else {
			a.Target.UID = ""
		}
		id := ids[key]
		if id == "" || deleted[key] != "" {
			id = fmt.Sprintf("target-%d", n+1)
			digest := "absent"
			if current != nil {
				digest, _ = api.DigestTarget(current)
			}
			bindings = append(bindings, api.TargetBinding{ID: id, Target: a.Target, Preconditions: api.Preconditions{SpecDigest: digest}, AfterActionID: deleted[key]})
			ids[key] = id
			delete(deleted, key)
		}
		a.BindingID = id
		if err := policy.AuthorizeAction(*a, current, i.Policy); err != nil {
			return nil, err
		}
		next, err := policy.BuildResult(*a, current)
		if err != nil {
			return nil, err
		}
		if next != nil && t.Spec.Scope != nil && !t.Spec.Scope.Matches(a.Target, next) {
			return nil, fmt.Errorf("proposed result does not match task scope")
		}
		staged[key] = next
		if a.Type == "DeleteResource" {
			deleted[key] = a.ID
		}
	}
	return bindings, nil
}
