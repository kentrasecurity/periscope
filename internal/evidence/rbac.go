package evidence

import (
	"github.com/kentrasecurity/periscope/internal/policy"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"strings"
)

func projectRBAC(u *unstructured.Unstructured) map[string]any {
	base := Project(u, policy.Config{})
	// Labels are required to diagnose selectors and scoped network policies.
	// Reuse structured credential sanitization rather than exporting metadata wholesale.
	if labels, ok, _ := unstructured.NestedMap(u.Object, "metadata", "labels"); ok {
		base["metadata"].(map[string]any)["labels"] = sanitize(labels)
	}
	if u.GetKind() == "Secret" {
		base["data"] = "[REDACTED]"
		return base
	}
	for _, key := range []string{"spec", "data"} {
		if value, ok := u.Object[key]; ok {
			base[key] = sanitize(value)
		}
	}
	return base
}

// RedactStructured sanitizes JSON-compatible values before serialization, so
// redaction of a string cannot corrupt the surrounding JSON representation.
func RedactStructured(v any) any { return sanitize(v) }

func sanitize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		result := map[string]any{}
		name, _ := x["name"].(string)
		sensitiveName := sensitiveField(name)
		for k, item := range x {
			if k == "automountServiceAccountToken" {
				if flag, ok := item.(bool); ok {
					result[k] = flag
					continue
				}
			}
			// valueFrom, envFrom and imagePullSecrets hold references, not values;
			// their nested fields are still sanitized below.
			_, scalar := item.(string)
			reference := ReferenceField(k) || StructuralReference(k) && !scalar
			if (sensitiveField(k) && !reference) || k == "annotations" || (k == "value" && sensitiveName) {
				result[k] = "[REDACTED]"
				continue
			}
			result[k] = sanitize(item)
		}
		return result
	case []any:
		result := make([]any, len(x))
		for i, item := range x {
			result[i] = sanitize(item)
		}
		return result
	case string:
		return Redact(x)
	default:
		return v
	}
}
func sensitiveField(k string) bool {
	s := strings.ToLower(k)
	for _, part := range []string{"secret", "password", "credential", "token", "authorization", "cookie", "auth", "privatekey", "api-key", "api_key"} {
		if strings.Contains(s, part) {
			return true
		}
	}
	return false
}
