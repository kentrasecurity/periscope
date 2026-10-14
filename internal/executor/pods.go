package executor

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sort"
)

type PodReader interface {
	List(context.Context, string, string, string, string) ([]*unstructured.Unstructured, error)
}

func CheckPods(ctx context.Context, r PodReader, d *unstructured.Unstructured) (bool, string, error) {
	if d == nil || d.GetKind() != "Deployment" {
		return false, "", fmt.Errorf("deployment required")
	}
	raw, ok, _ := unstructured.NestedMap(d.Object, "spec", "selector")
	if !ok {
		return false, "", fmt.Errorf("deployment selector unavailable")
	}
	var selector metav1.LabelSelector
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &selector); err != nil {
		return false, "", err
	}
	sel, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil || sel.Empty() {
		return false, "", fmt.Errorf("bounded selector required")
	}
	sets, err := r.List(ctx, "apps/v1", "ReplicaSet", d.GetNamespace(), sel.String())
	if err != nil {
		return false, "", err
	}
	owners := map[string]bool{}
	for _, rs := range sets {
		for _, owner := range rs.GetOwnerReferences() {
			if string(owner.UID) == string(d.GetUID()) && owner.Kind == "Deployment" && owner.Controller != nil && *owner.Controller {
				owners[string(rs.GetUID())] = true
			}
		}
	}
	pods, err := r.List(ctx, "v1", "Pod", d.GetNamespace(), sel.String())
	if err != nil {
		return false, "", err
	}
	wanted, ok, _ := unstructured.NestedInt64(d.Object, "spec", "replicas")
	if !ok {
		wanted = 1
	}
	records := []string{}
	count := int64(0)
	for _, p := range pods {
		owned := false
		for _, owner := range p.GetOwnerReferences() {
			if owner.Kind == "ReplicaSet" && owners[string(owner.UID)] && owner.Controller != nil && *owner.Controller {
				owned = true
			}
		}
		if !owned || !sel.Matches(labels.Set(p.GetLabels())) {
			continue
		}
		if p.GetDeletionTimestamp() != nil {
			return false, "", nil
		}
		count++
		healthy, fingerprint, err := CheckPod(p)
		if err != nil || !healthy {
			return false, "", err
		}
		records = append(records, fingerprint)
	}

	if wanted < 1 || count != wanted {
		return false, "", nil
	}
	sort.Strings(records)
	digest, err := api.Hash(records)
	return err == nil, digest, err
}
