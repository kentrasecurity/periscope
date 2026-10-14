package policy

import (
	"encoding/json"
	"fmt"
	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func BuildResult(a api.Action, current *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	switch a.Type {
	case "DeleteResource":
		return nil, nil
	case "CreateResource":
		b, e := json.Marshal(a.Object)
		if e != nil {
			return nil, e
		}
		var o map[string]any
		if e = json.Unmarshal(b, &o); e != nil {
			return nil, e
		}
		u := &unstructured.Unstructured{Object: o}
		if u.GetAPIVersion() != a.Target.APIVersion || u.GetKind() != a.Target.Kind || u.GetName() != a.Target.Name || u.GetNamespace() != a.Target.Namespace || u.GetUID() != "" {
			return nil, fmt.Errorf("create object identity mismatch: action target is %s; object is %s/%s/%s/%s; the object must match action.target exactly and omit UID", api.ResourceKey(a.Target), u.GetNamespace(), u.GetAPIVersion(), u.GetKind(), u.GetName())
		}
		return u, nil
	case "RestartWorkload":
		if current == nil {
			return nil, fmt.Errorf("missing workload")
		}
		u := current.DeepCopy()
		annotations, _, e := unstructured.NestedStringMap(u.Object, "spec", "template", "metadata", "annotations")
		if e != nil {
			return nil, e
		}
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[api.OperationAnnotation] = a.ID
		if e = unstructured.SetNestedStringMap(u.Object, annotations, "spec", "template", "metadata", "annotations"); e != nil {
			return nil, e
		}
		return u, nil
	case "PatchResource":
		if current == nil {
			return nil, fmt.Errorf("missing target")
		}
		ops, e := json.Marshal(a.Patch)
		if e != nil {
			return nil, e
		}
		patch, e := jsonpatch.DecodePatch(ops)
		if e != nil {
			return nil, e
		}
		before, e := json.Marshal(current.Object)
		if e != nil {
			return nil, e
		}
		after, e := patch.Apply(before)
		if e != nil {
			return nil, e
		}
		var o map[string]any
		if e = json.Unmarshal(after, &o); e != nil {
			return nil, e
		}
		return &unstructured.Unstructured{Object: o}, nil
	default:
		return nil, fmt.Errorf("unknown action type")
	}
}
