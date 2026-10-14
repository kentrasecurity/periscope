package executor

import (
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func CheckResourceHealth(u *unstructured.Unstructured) (bool, string, error) {
	if u == nil || u.GetDeletionTimestamp() != nil {
		return false, "", nil
	}
	if u.GetKind() == "Pod" && u.GetAPIVersion() == "v1" {
		return CheckPod(u)
	}
	if u.GetKind() == "Deployment" && u.GetAPIVersion() == "apps/v1" {
		return CheckResource(u, api.Verification{Type: "DeploymentRecovery"})
	}
	switch u.GetKind() {
	case "Service", "Ingress", "PodDisruptionBudget", "NetworkPolicy", "CronJob", "ConfigMap":
		return checkServiceShape(u)
	case "PersistentVolumeClaim":
		return checkClaim(u)
	case "Job":
		return checkJob(u)
	case "ReplicaSet":
		return checkReplicaSet(u)
	}
	generation, found, _ := unstructured.NestedInt64(u.Object, "status", "observedGeneration")
	if found && generation < u.GetGeneration() {
		return false, "", nil
	}
	if u.GetKind() == "StatefulSet" {
		wanted, exists, _ := unstructured.NestedInt64(u.Object, "spec", "replicas")
		if !exists {
			wanted = 1
		}
		ready, _, _ := unstructured.NestedInt64(u.Object, "status", "readyReplicas")
		updated, _, _ := unstructured.NestedInt64(u.Object, "status", "updatedReplicas")
		partition, _, _ := unstructured.NestedInt64(u.Object, "spec", "updateStrategy", "rollingUpdate", "partition")
		required := wanted - partition
		if required < 0 {
			required = 0
		}
		current, _, _ := unstructured.NestedString(u.Object, "status", "currentRevision")
		revision, _, _ := unstructured.NestedString(u.Object, "status", "updateRevision")
		complete := updated >= required && (partition > 0 || wanted == 0 || current != "" && current == revision)
		fingerprint, _ := api.Hash([]any{string(u.GetUID()), u.GetGeneration(), ready, wanted, updated, current, revision})
		return ready == wanted && generation >= u.GetGeneration() && complete, fingerprint, nil
	}
	if u.GetKind() == "DaemonSet" {
		wanted, _, _ := unstructured.NestedInt64(u.Object, "status", "desiredNumberScheduled")
		ready, _, _ := unstructured.NestedInt64(u.Object, "status", "numberReady")
		updated, _, _ := unstructured.NestedInt64(u.Object, "status", "updatedNumberScheduled")
		unavailable, _, _ := unstructured.NestedInt64(u.Object, "status", "numberUnavailable")
		fingerprint, _ := api.Hash([]any{string(u.GetUID()), u.GetGeneration(), ready, wanted, updated})
		return wanted > 0 && ready == wanted && updated == wanted && unavailable == 0 && generation >= u.GetGeneration(), fingerprint, nil
	}
	conditions, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	recognized := false
	healthy := true
	for _, c := range conditions {
		m, _ := c.(map[string]any)
		if observed, ok := m["observedGeneration"]; ok {
			switch value := observed.(type) {
			case int64:
				if value < u.GetGeneration() {
					healthy = false
				}
			case float64:
				if value < float64(u.GetGeneration()) {
					healthy = false
				}
			}
		}
		switch m["type"] {
		case "Ready", "Available", "AbleToScale":
			recognized = true
			healthy = healthy && m["status"] == "True"
		case "ScalingActive":
			// A HorizontalPodAutoscaler is intentionally inactive when scaling is disabled.
			recognized = true
			healthy = healthy && (m["status"] == "True" || m["reason"] == "ScalingDisabled")
		case "Failed", "Degraded", "ReplicaFailure":
			recognized = true
			healthy = healthy && m["status"] == "False"
		}
	}
	if !recognized {
		return false, "", fmt.Errorf("no supported observed health condition; goal checks required")
	}
	normalized := []any{string(u.GetUID()), u.GetGeneration()}
	for _, c := range conditions {
		m, _ := c.(map[string]any)
		normalized = append(normalized, []any{m["type"], m["status"], m["reason"], m["observedGeneration"]})
	}
	fingerprint, err := api.Hash(normalized)
	return healthy, fingerprint, err
}
