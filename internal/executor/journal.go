package executor

import (
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"maps"
	"slices"
	"strings"
)

func Operation(p *kube.Plan, id string) string {
	hash, _ := api.Hash([]string{string(p.Object.GetUID()), id})
	return hash
}
func PrepareResult(p *kube.Plan, a api.Action, current *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	operation := Operation(p, a.ID)
	if a.Type == "RestartWorkload" {
		a.ID = operation
	}
	result, e := policy.BuildResult(a, current)
	if e != nil || result == nil {
		return result, e
	}
	annotations := result.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[api.Group+"/plan"] = p.Object.GetName()
	if p.Object.GetNamespace() != a.Target.Namespace {
		annotations[api.Group+"/plan-namespace"] = p.Object.GetNamespace()
	}
	annotations[api.OperationAnnotation] = operation
	result.SetAnnotations(annotations)
	return result, nil
}
func ResultDigest(u *unstructured.Unstructured, a api.Action) (string, error) {
	if u == nil {
		return "absent", nil
	}
	copy := u.DeepCopy()
	if a.Type == "CreateResource" {
		copy.SetUID("")
		shape := (&unstructured.Unstructured{Object: a.Object}).DeepCopy()
		shape.SetUID("")
		annotations := shape.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		for _, key := range []string{api.OperationAnnotation, api.Group + "/plan", api.Group + "/plan-namespace"} {
			if value, present := copy.GetAnnotations()[key]; present {
				annotations[key] = value
			}
		}
		if len(annotations) > 0 {
			shape.SetAnnotations(annotations)
		}
		projected, err := projectCreation(copy.Object, shape.Object)
		if err != nil {
			return "", err
		}
		copy.Object = projected.(map[string]any)
		if len(a.SecretSources) > 0 {
			// Values are filled at execution and never hashed: the result must
			// carry exactly the planned keys, whatever their values.
			planned := secretKeys(a.SecretSources)
			if written := dataKeys(u); len(written) > 0 && !slices.Equal(written, planned) {
				return api.Hash([]any{"secret keys differ from plan", written})
			}
			copy.Object["data"] = planned
		}
	}
	if a.Type != "CreateResource" {
		if owned := ownedAnnotations(a); owned != nil {
			annotations := map[string]string{}
			for key, value := range copy.GetAnnotations() {
				if owned[key] {
					annotations[key] = value
				}
			}
			copy.SetAnnotations(annotations)
		}
	}
	return api.DigestTarget(copy)
}

// ownedAnnotations are the metadata annotations a result digest covers for a
// write to an existing object: the operator's markers and keys the action
// patches (nil: all, when the patch replaces the whole map). Other controllers
// (Rancher, GitOps, cert-manager) annotate objects after a write; that must
// not make an applied write look unapplied. Admission still requires the
// write itself to carry exactly the planned annotations (SameAnnotations).
func ownedAnnotations(a api.Action) map[string]bool {
	owned := map[string]bool{api.OperationAnnotation: true, api.Group + "/plan": true, api.Group + "/plan-namespace": true}
	for _, op := range a.Patch {
		if op.Path == "/metadata" || op.Path == "/metadata/annotations" {
			return nil
		}
		if key, ok := strings.CutPrefix(op.Path, "/metadata/annotations/"); ok {
			owned[strings.ReplaceAll(strings.ReplaceAll(key, "~1", "/"), "~0", "~")] = true
		}
	}
	return owned
}

// SameAnnotations reports whether a write carries exactly the annotations of
// the approved result.
func SameAnnotations(desired, written *unstructured.Unstructured) bool {
	if desired == nil || written == nil {
		return desired == nil && written == nil
	}
	return maps.Equal(desired.GetAnnotations(), written.GetAnnotations())
}

func secretKeys(sources map[string]api.SecretSource) []any {
	keys := []any{}
	for _, k := range slices.Sorted(maps.Keys(sources)) {
		keys = append(keys, k)
	}
	return keys
}

// dataKeys lists a Secret's keys, never its values.
func dataKeys(u *unstructured.Unstructured) []any {
	seen := map[string]bool{}
	for _, field := range []string{"data", "stringData"} {
		values, _, _ := unstructured.NestedMap(u.Object, field)
		for k := range values {
			seen[k] = true
		}
	}
	keys := []any{}
	for _, k := range slices.Sorted(maps.Keys(seen)) {
		keys = append(keys, k)
	}
	return keys
}

// Creation approves the submitted manifest plus the operation marker. Cluster
// admission may add omitted fields; every explicitly supplied field must survive
// unchanged. Explicit arrays retain their length and order.
func projectCreation(actual, shape any) (any, error) {
	switch proposed := shape.(type) {
	case map[string]any:
		object, ok := actual.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("creation result changed object type")
		}
		out := map[string]any{}
		for key, value := range proposed {
			observed, present := object[key]
			if !present {
				return nil, fmt.Errorf("creation result omitted proposed field %s", key)
			}
			projected, err := projectCreation(observed, value)
			if err != nil {
				return nil, err
			}
			out[key] = projected
		}
		return out, nil
	case []any:
		list, ok := actual.([]any)
		if !ok || len(list) != len(proposed) {
			return nil, fmt.Errorf("creation result changed proposed array length/type")
		}
		out := make([]any, len(proposed))
		for n, value := range proposed {
			projected, err := projectCreation(list[n], value)
			if err != nil {
				return nil, err
			}
			out[n] = projected
		}
		return out, nil
	default:
		return actual, nil
	}
}
