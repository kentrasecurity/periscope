package executor

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/observation"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"strings"
	"testing"
	"time"
)

type fakeProbe struct {
	vantage string
	success bool
}

func (f fakeProbe) Check(_ context.Context, t api.TargetRef, _ observation.ProbeRequest) (observation.ProbeResult, error) {
	return observation.ProbeResult{Success: f.success, Vantage: f.vantage, ObservedAt: time.Now()}, nil
}
func TestNetworkGoalRequiresOriginalPodVantage(t *testing.T) {
	b := testkit.NewMemory()
	b.PutResource(testkit.Resource("v1", "Pod", "demo", "app", "poduid", nil))
	check := api.Check{ID: "network", Type: "HTTP", Target: api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "app"}, Endpoint: "http://service.demo:8080/", Vantage: "monitored-pod"}
	for _, vantage := range []string{"agent-context", "pod:other", "pod:poduid"} {
		results, err := (CheckEvaluator{Reader: b, Probe: fakeProbe{vantage: vantage, success: true}}).EvaluateChecks(context.Background(), []api.Check{check})
		if err != nil {
			t.Fatal(err)
		}
		if ChecksHealthy(results) != (vantage == "pod:poduid") {
			t.Fatal("wrong vantage satisfied Pod network goal")
		}
	}
}

type fixedMetrics struct{ content string }

func (f fixedMetrics) Definition() observation.ToolDefinition {
	return observation.ToolDefinition{Name: "query_prometheus"}
}
func (f fixedMetrics) Call(context.Context, api.Scope, observation.ToolCall) (observation.ToolResult, error) {
	return observation.ToolResult{Content: []byte(f.content)}, nil
}

func TestPrometheusCheckReportsObservedValues(t *testing.T) {
	b := testkit.NewMemory()
	b.PutResource(testkit.Resource("apps/v1", "Deployment", "demo", "worker", "worker-uid", nil))
	c := CheckEvaluator{Reader: b, Metrics: fixedMetrics{`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"0.93"]}]}}`}}
	results, err := c.EvaluateChecks(context.Background(), []api.Check{{ID: "throttle", Type: "Prometheus", Query: "throttle_ratio > bool 0.25", Expected: "0", Target: api.TargetRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "demo", Name: "worker"}}})
	if err != nil || results[0].Healthy || !strings.Contains(results[0].Observation, "throttle_ratio > bool 0.25 returned 0.93 across 1 series, expected 0") {
		t.Fatalf("metric observation lacks values: %+v %v", results, err)
	}
}
