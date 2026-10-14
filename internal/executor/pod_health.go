package executor

import (
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sort"
	"strings"
)

// CheckPod requires evidence for every declared container, not a Ready flag alone.
func CheckPod(p *unstructured.Unstructured) (bool, string, error) {
	if p == nil {
		return false, "", nil
	}
	if p.GetAPIVersion() != "v1" || p.GetKind() != "Pod" {
		return false, "", fmt.Errorf("PodRecovery requires a v1 Pod")
	}
	if p.GetDeletionTimestamp() != nil {
		return false, "", nil
	}
	phase, _, _ := unstructured.NestedString(p.Object, "status", "phase")
	if phase != "Running" {
		return false, "", nil
	}
	observed, present, _ := unstructured.NestedInt64(p.Object, "status", "observedGeneration")
	if present && observed < p.GetGeneration() {
		return false, "", nil
	}
	conditions, _, _ := unstructured.NestedSlice(p.Object, "status", "conditions")
	ready := false
	for _, c := range conditions {
		m, _ := c.(map[string]any)
		if m["type"] == "Ready" && m["status"] == "True" {
			ready = true
		}
	}
	if !ready {
		return false, "", nil
	}
	records := []string{string(p.GetUID())}
	for _, group := range []struct {
		spec, status string
		init         bool
	}{{"containers", "containerStatuses", false}, {"initContainers", "initContainerStatuses", true}} {
		declared, _, _ := unstructured.NestedSlice(p.Object, "spec", group.spec)
		if !group.init && len(declared) == 0 {
			return false, "", fmt.Errorf("Pod has no application containers")
		}
		statuses, _, _ := unstructured.NestedSlice(p.Object, "status", group.status)
		byName := map[string]map[string]any{}
		for _, s := range statuses {
			m, ok := s.(map[string]any)
			if !ok {
				return false, "", nil
			}
			name, _ := m["name"].(string)
			if name == "" || byName[name] != nil {
				return false, "", nil
			}
			byName[name] = m
		}
		if len(byName) != len(declared) {
			return false, "", nil
		}
		for _, d := range declared {
			spec, ok := d.(map[string]any)
			if !ok {
				return false, "", nil
			}
			name, _ := spec["name"].(string)
			s := byName[name]
			if s == nil {
				return false, "", nil
			}
			desiredImage, _ := spec["image"].(string)
			observedImage, _ := s["image"].(string)
			if desiredImage == "" || observedImage == "" || canonicalImage(desiredImage) != canonicalImage(observedImage) {
				return false, "", nil
			}
			state, _ := s["state"].(map[string]any)
			if group.init && spec["restartPolicy"] != "Always" {
				terminated, ok := state["terminated"].(map[string]any)
				if !ok || fmt.Sprint(terminated["exitCode"]) != "0" {
					return false, "", nil
				}
			} else {
				if _, ok := state["running"].(map[string]any); !ok || s["ready"] != true {
					return false, "", nil
				}
			}
			id, _ := s["containerID"].(string)
			if id == "" {
				return false, "", nil
			}
			records = append(records, fmt.Sprintf("%s/%s/%v/%v/%v", name, id, s["restartCount"], s["imageID"], spec["image"]))
		}
	}
	sort.Strings(records)
	fingerprint, err := api.Hash(records)
	return err == nil, fingerprint, err
}

func canonicalImage(image string) string {
	image = strings.TrimPrefix(image, "docker-pullable://")
	parts := strings.Split(image, "/")
	if len(parts) == 1 {
		image = "docker.io/library/" + image
	} else if !strings.ContainsAny(parts[0], ".:") && parts[0] != "localhost" {
		image = "docker.io/" + image
	}
	last := image[strings.LastIndex(image, "/")+1:]
	if !strings.Contains(last, ":") && !strings.Contains(image, "@") {
		image += ":latest"
	}
	return image
}
