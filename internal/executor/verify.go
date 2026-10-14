package executor

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"net/http"
	"time"
)

func CheckResource(u *unstructured.Unstructured, v api.Verification) (bool, string, error) {
	if v.Type == "ResourceAbsent" {
		return u == nil, "absent", nil
	}
	if u == nil {
		return false, "", nil
	}
	switch v.Type {
	case "ResourceHealthy":
		return CheckResourceHealth(u)
	case "PodRecovery":
		return CheckPod(u)
	case "ResourceExists":
		hash, e := api.DigestTarget(u)
		return true, hash, e
	case "FieldEquals":
		current, ok := evidence.Lookup(u.Object, v.Path)
		a, _ := api.Hash(current)
		b, _ := api.Hash(v.Expected)
		return ok && a == b, a, nil
	case "DeploymentRecovery":
		if u.GetKind() != "Deployment" {
			return false, "", fmt.Errorf("wrong workload verifier")
		}
		wanted, ok, _ := unstructured.NestedInt64(u.Object, "spec", "replicas")
		if !ok {
			wanted = 1
		}
		if wanted < 1 {
			return false, "", fmt.Errorf("zero replicas cannot prove application recovery")
		}
		ready, _, _ := unstructured.NestedInt64(u.Object, "status", "readyReplicas")
		available, _, _ := unstructured.NestedInt64(u.Object, "status", "availableReplicas")
		updated, _, _ := unstructured.NestedInt64(u.Object, "status", "updatedReplicas")
		observed, _, _ := unstructured.NestedInt64(u.Object, "status", "observedGeneration")
		return ready == wanted && available == wanted && updated == wanted && observed >= u.GetGeneration(), fmt.Sprintf("%d/%d/%d", ready, available, updated), nil
	default:
		return false, "", fmt.Errorf("unsupported recovery verifier")
	}
}
func CheckHealth(ctx context.Context, url string) bool {
	if url == "" {
		return true
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return fmt.Errorf("health redirects forbidden") }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		return false
	}
	response, e := client.Do(req)
	if e != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode >= 200 && response.StatusCode < 300
}
