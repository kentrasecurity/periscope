package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func Hash(value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

func DigestPlan(p PlanSpec) (string, error) { p.Digest = ""; return Hash(p) }

// DigestTarget binds identity and user configuration, not asynchronous API status.
func DigestTarget(u *unstructured.Unstructured) (string, error) {
	if u == nil {
		return "", fmt.Errorf("target is absent")
	}
	copy := u.DeepCopy()
	delete(copy.Object, "status")
	m, ok := copy.Object["metadata"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("target metadata missing")
	}
	for _, key := range []string{"resourceVersion", "generation", "managedFields", "creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds"} {
		delete(m, key)
	}
	if copy.GetAPIVersion() == "apps/v1" && copy.GetKind() == "Deployment" {
		if annotations, ok := m["annotations"].(map[string]any); ok {
			delete(annotations, "deployment.kubernetes.io/revision")
			if len(annotations) == 0 {
				delete(m, "annotations")
			}
		}
	}
	return Hash(copy.Object)
}
