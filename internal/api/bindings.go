package api

import (
	"fmt"
	"strings"
)

func ResourceKey(t TargetRef) string {
	return t.Namespace + "/" + t.APIVersion + "/" + t.Kind + "/" + t.Name
}

// ResolveBindings validates representation, dependencies and exact action identity.
func ResolveBindings(p PlanSpec) (map[string]TargetBinding, error) {
	if len(p.Targets) == 0 {
		for _, a := range p.Actions {
			if a.BindingID != "" {
				return nil, fmt.Errorf("legacy action cannot reference a binding")
			}
		}
		return map[string]TargetBinding{"": {Target: p.TargetRef, Preconditions: p.Preconditions}}, nil
	}
	if len(p.Targets) > 20 {
		return nil, fmt.Errorf("too many target bindings")
	}
	out := map[string]TargetBinding{}
	actions := map[string]int{}
	for n, a := range p.Actions {
		if a.ID == "" || actions[a.ID] != 0 {
			return nil, fmt.Errorf("duplicate or empty action ID")
		}
		actions[a.ID] = n + 1
	}
	primary := false
	for _, b := range p.Targets {
		if b.ID == "" || len(b.ID) > 128 || out[b.ID].ID != "" || b.Target.Namespace == "" || b.Target.Name == "" || b.Target.APIVersion == "" || b.Target.Kind == "" || b.Preconditions.SpecDigest == "" {
			return nil, fmt.Errorf("invalid target binding")
		}
		if b.AfterActionID != "" {
			index := actions[b.AfterActionID] - 1
			if index < 0 || p.Actions[index].Type != "DeleteResource" || ResourceKey(p.Actions[index].Target) != ResourceKey(b.Target) || b.Target.UID != "" || b.Preconditions.SpecDigest != "absent" {
				return nil, fmt.Errorf("post-action binding requires explicit same-resource deletion")
			}
		}
		if b.Target == p.TargetRef && b.Preconditions == p.Preconditions && b.AfterActionID == "" {
			primary = true
		}
		out[b.ID] = b
	}
	if !primary {
		return nil, fmt.Errorf("primary goal target must be bound")
	}
	for n, a := range p.Actions {
		b, ok := out[a.BindingID]
		if !ok || a.Target != b.Target {
			return nil, fmt.Errorf("action has no exact binding")
		}
		if b.AfterActionID != "" && (actions[b.AfterActionID] > n || a.Type != "CreateResource") {
			return nil, fmt.Errorf("absence dependency must precede creation")
		}
	}
	return out, nil
}

// ClaimKey ignores UID and API version: recreation and alternate served versions share the fence.
func ClaimKey(t TargetRef) string {
	group := ""
	if strings.Contains(t.APIVersion, "/") {
		group = strings.SplitN(t.APIVersion, "/", 2)[0]
	}
	return t.Namespace + "/" + group + "/" + t.Kind + "/" + t.Name
}
