package executor

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"sort"
)

// NoHealthSemantics lists namespaced kinds that only carry configuration or
// bookkeeping. Discovery skips them instead of reporting a coverage gap; the
// workloads that consume them are checked directly.
func NoHealthSemantics(kind string) bool {
	switch kind {
	case "Secret", "ServiceAccount", "Endpoints", "EndpointSlice", "ControllerRevision", "Role", "RoleBinding", "Lease", "Event", "LimitRange", "ResourceQuota", "PodTemplate", "CSIStorageCapacity", "Binding", "LocalSubjectAccessReview":
		return true
	}
	return false
}

// checkServiceShape accepts a reference kind structurally; whether its
// references resolve needs a reader and is evaluated by CheckReferences.
func checkServiceShape(u *unstructured.Unstructured) (bool, string, error) {
	fingerprint, err := api.Hash([]any{string(u.GetUID()), u.GetGeneration()})
	return err == nil, fingerprint, err
}

// CheckService reports a selector Service unhealthy only when nothing in the
// namespace can ever back it: no matching Pod and no workload template with
// matching labels. Intentionally scaled-down workloads remain healthy.
func CheckService(ctx context.Context, r PodReader, u *unstructured.Unstructured) (bool, string, error) {
	if u == nil || u.GetKind() != "Service" {
		return false, "", fmt.Errorf("Service required")
	}
	healthy, fingerprint, err := checkServiceShape(u)
	serviceType, _, _ := unstructured.NestedString(u.Object, "spec", "type")
	selector, _, _ := unstructured.NestedStringMap(u.Object, "spec", "selector")
	if err != nil || serviceType == "ExternalName" || len(selector) == 0 {
		return healthy, fingerprint, err
	}
	sel := labels.SelectorFromSet(selector)
	pods, err := r.List(ctx, "v1", "Pod", u.GetNamespace(), sel.String())
	if err != nil {
		return false, "", err
	}
	for _, p := range pods {
		if p.GetDeletionTimestamp() == nil && sel.Matches(labels.Set(p.GetLabels())) {
			return true, fingerprint, nil
		}
	}
	for _, kind := range []struct{ version, kind string }{{"apps/v1", "Deployment"}, {"apps/v1", "StatefulSet"}, {"apps/v1", "DaemonSet"}, {"batch/v1", "Job"}} {
		items, err := r.List(ctx, kind.version, kind.kind, u.GetNamespace(), "")
		if err != nil {
			return false, "", err
		}
		for _, w := range items {
			template, _, _ := unstructured.NestedStringMap(w.Object, "spec", "template", "metadata", "labels")
			if sel.Matches(labels.Set(template)) {
				return true, fingerprint, nil
			}
		}
	}
	missing, err := api.Hash([]any{string(u.GetUID()), u.GetGeneration(), "no-backends"})
	return false, missing, err
}

// NearestBackend names the workload whose template labels are closest to a
// Service selector that matches nothing (every selector key present, smallest
// total edit distance of at most two characters per key), so a typo is not
// "repaired" by pointing the Service at another application. It returns "" when
// no workload is that close.
func NearestBackend(ctx context.Context, r PodReader, u *unstructured.Unstructured) string {
	selector, _, _ := unstructured.NestedStringMap(u.Object, "spec", "selector")
	if len(selector) == 0 {
		return ""
	}
	best, bestDistance := "", 2*len(selector)+1
	for _, kind := range []struct{ version, kind string }{{"apps/v1", "Deployment"}, {"apps/v1", "StatefulSet"}, {"apps/v1", "DaemonSet"}} {
		items, err := r.List(ctx, kind.version, kind.kind, u.GetNamespace(), "")
		if err != nil {
			continue
		}
		for _, w := range items {
			template, _, _ := unstructured.NestedStringMap(w.Object, "spec", "template", "metadata", "labels")
			distance, complete := 0, true
			for key, value := range selector {
				have, ok := template[key]
				if !ok {
					complete = false
					break
				}
				distance += editDistance(value, have)
			}
			if complete && distance < bestDistance {
				best, bestDistance = fmt.Sprintf("%s/%s (template labels %s)", kind.kind, w.GetName(), labels.SelectorFromSet(template)), distance
			}
		}
	}
	return best
}

func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current := make([]int, len(b)+1)
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous = current
	}
	return previous[len(b)]
}

// checkClaim treats a Pending claim as a failure only after the scheduler has
// selected a node for its consumer; WaitForFirstConsumer claims are otherwise
// legitimately Pending.
func checkClaim(u *unstructured.Unstructured) (bool, string, error) {
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	fingerprint, err := api.Hash([]any{string(u.GetUID()), u.GetGeneration(), phase})
	if err != nil {
		return false, "", err
	}
	switch phase {
	case "Bound":
		return true, fingerprint, nil
	case "Pending":
		_, selected := u.GetAnnotations()["volume.kubernetes.io/selected-node"]
		return !selected, fingerprint, nil
	default:
		return false, fingerprint, nil
	}
}

// checkJob treats a running Job as healthy; Complete Jobs are excluded by
// discovery and failed Jobs report the failure.
func checkJob(u *unstructured.Unstructured) (bool, string, error) {
	conditions, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	healthy := true
	normalized := []any{string(u.GetUID()), u.GetGeneration()}
	for _, c := range conditions {
		m, _ := c.(map[string]any)
		if (m["type"] == "Failed" || m["type"] == "FailureTarget") && m["status"] == "True" {
			healthy = false
			normalized = append(normalized, m["type"], m["reason"])
		}
	}
	fingerprint, err := api.Hash(normalized)
	return healthy, fingerprint, err
}

func checkReplicaSet(u *unstructured.Unstructured) (bool, string, error) {
	wanted, exists, _ := unstructured.NestedInt64(u.Object, "spec", "replicas")
	if !exists {
		wanted = 1
	}
	ready, _, _ := unstructured.NestedInt64(u.Object, "status", "readyReplicas")
	observed, _, _ := unstructured.NestedInt64(u.Object, "status", "observedGeneration")
	healthy := ready == wanted && observed >= u.GetGeneration()
	conditions, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	for _, c := range conditions {
		m, _ := c.(map[string]any)
		if m["type"] == "ReplicaFailure" && m["status"] == "True" {
			healthy = false
		}
	}
	fingerprint, err := api.Hash([]any{string(u.GetUID()), u.GetGeneration(), ready, wanted})
	return healthy, fingerprint, err
}

// FailureSignature identifies a failure by its kind rather than its counters.
// Restart counts, timestamps and the CrashLoopBackOff/running alternation are
// excluded, so per-incident attempt limits hold for a persistently failing
// object while a spec change (generation) or a different reason opens a new one.
func FailureSignature(u *unstructured.Unstructured) string {
	if u == nil {
		return "absent"
	}
	parts := []string{string(u.GetUID()), fmt.Sprint(u.GetGeneration())}
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	parts = append(parts, "phase="+phase)
	conditions, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	for _, c := range conditions {
		m, _ := c.(map[string]any)
		kind, _ := m["type"].(string)
		// Pod readiness flaps with container restarts; container reasons carry the cause.
		if u.GetKind() == "Pod" && (kind == "Ready" || kind == "ContainersReady") {
			continue
		}
		parts = append(parts, fmt.Sprintf("condition=%s/%v/%v", kind, m["status"], m["reason"]))
	}
	for _, group := range []string{"initContainerStatuses", "containerStatuses"} {
		statuses, _, _ := unstructured.NestedSlice(u.Object, "status", group)
		for _, s := range statuses {
			m, _ := s.(map[string]any)
			parts = append(parts, fmt.Sprintf("%s=%v/%s", group, m["name"], containerReason(m)))
		}
	}
	sort.Strings(parts[2:])
	hash, _ := api.Hash(parts)
	return hash
}

func containerReason(status map[string]any) string {
	last, _, _ := unstructured.NestedString(status, "lastState", "terminated", "reason")
	restarts, _, _ := unstructured.NestedInt64(status, "restartCount")
	if restarts > 0 && last != "" && last != "Completed" {
		return "restarting:" + last
	}
	if reason, ok, _ := unstructured.NestedString(status, "state", "waiting", "reason"); ok {
		if reason == "ErrImagePull" {
			reason = "ImagePullBackOff"
		}
		return "waiting:" + reason
	}
	if reason, ok, _ := unstructured.NestedString(status, "state", "terminated", "reason"); ok {
		return "terminated:" + reason
	}
	return "running"
}
