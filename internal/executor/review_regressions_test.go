package executor

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/observation"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"sync"
	"testing"
	"time"
)

type nsClaims struct {
	*testkit.Memory
	leases map[string]string
}

func (b nsClaims) Claim(_ context.Context, ns, key, holder string) (bool, error) {
	key = ns + "/" + key
	if prior := b.leases[key]; prior != "" && prior != holder {
		return false, nil
	}
	b.leases[key] = holder
	return true, nil
}
func (b nsClaims) Release(_ context.Context, ns, key, holder string) error {
	key = ns + "/" + key
	if b.leases[key] == holder {
		delete(b.leases, key)
	}
	return nil
}
func TestClaimsSharedAcrossRecordNamespacesAndReplacement(t *testing.T) {
	e, b, p, _ := execution(t)
	backend := nsClaims{Memory: b, leases: map[string]string{}}
	e.Backend = backend
	e.Policy.CoordinationNamespace = "demo"
	other := *p
	other.Object = p.Object.DeepCopy()
	other.Object.SetNamespace("other")
	other.Object.SetUID("other-plan")
	if acquired, err := e.claimAll(context.Background(), "demo", p); err != nil || !acquired {
		t.Fatal("first claim failed")
	}
	if acquired, _ := e.claimAll(context.Background(), "other", &other); acquired {
		t.Fatal("different record namespace bypassed same-target claim")
	}
	other.Spec = p.Spec
	other.Spec.TargetRef.UID = "replacement-uid"
	other.Spec.Targets = nil
	if acquired, _ := e.claimAll(context.Background(), "other", &other); acquired {
		t.Fatal("UID replacement bypassed logical target claim")
	}
}
func TestResourceHealthyCannotBypassPodOrStaleCondition(t *testing.T) {
	pod := healthyStandalonePod()
	pod.Object["spec"].(map[string]any)["containers"] = append(pod.Object["spec"].(map[string]any)["containers"].([]any), map[string]any{"name": "missing", "image": "working"})
	if healthy, _, _ := CheckResourceHealth(pod); healthy {
		t.Fatal("generic Ready bypassed complete Pod check")
	}
	custom := testkit.Resource("custom.test/v1", "Widget", "demo", "widget", "uid", map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True", "observedGeneration": int64(1)}}}})
	custom.SetGeneration(2)
	if healthy, _, _ := CheckResourceHealth(custom); healthy {
		t.Fatal("stale condition satisfied current generation")
	}
}
func TestOriginalCheckTimingCannotBeWeakened(t *testing.T) {
	e, _, p, _ := execution(t)
	p.Spec.Checks = []api.Check{{ID: "goal", Type: "FieldEquals", Target: p.Spec.TargetRef, Path: "/data/mode", Expected: "healthy", TimeoutSeconds: 300, StableWindowSeconds: 120}}
	if err := policy.ValidatePlan(api.TaskSpec{TargetRef: p.Spec.TargetRef, Mode: "HumanApproved"}, p.Spec, e.Policy); err == nil {
		t.Fatal("one second plan replaced 120 second original check")
	}
}

type parallelProbe struct {
	mu          sync.Mutex
	active, max int
}

func (p *parallelProbe) Check(ctx context.Context, t api.TargetRef, _ observation.ProbeRequest) (observation.ProbeResult, error) {
	p.mu.Lock()
	p.active++
	if p.active > p.max {
		p.max = p.active
	}
	p.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-time.After(30 * time.Millisecond):
	}
	p.mu.Lock()
	p.active--
	p.mu.Unlock()
	return observation.ProbeResult{Success: true, Vantage: "pod:" + t.UID, ObservedAt: time.Now()}, nil
}
func TestOriginalChecksUseBoundedParallelObservations(t *testing.T) {
	b := testkit.NewMemory()
	b.PutResource(testkit.Resource("v1", "Pod", "demo", "app", "uid", nil))
	probe := &parallelProbe{}
	checks := []api.Check{}
	for _, id := range []string{"a", "b", "c"} {
		checks = append(checks, api.Check{ID: id, Type: "HTTP", Target: api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "app"}, Vantage: "monitored-pod", Endpoint: "http://service/"})
	}
	results, err := (CheckEvaluator{Reader: b, Probe: probe}).EvaluateChecks(context.Background(), checks)
	if err != nil || !ChecksHealthy(results) || probe.max < 3 {
		t.Fatal("sequential checks can exceed webhook deadline")
	}
}

var _ *kube.Plan
