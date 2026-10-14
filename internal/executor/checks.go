package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/observation"
	"strconv"
	"strings"
	"sync"
	"time"
)

type CheckEvaluator struct {
	Reader  TargetReader
	Pods    PodReader
	Probe   observation.ProbeClient
	Metrics observation.Tool
	Scope   api.Scope
}

func (c CheckEvaluator) EvaluateChecks(ctx context.Context, checks []api.Check) ([]api.CheckResult, error) {
	if len(checks) < 1 || len(checks) > 32 {
		return nil, fmt.Errorf("original checks require 1..32 observations")
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	results := make([]api.CheckResult, len(checks))
	var wait sync.WaitGroup
	for n, check := range checks {
		wait.Add(1)
		go func(n int, check api.Check) { defer wait.Done(); results[n] = c.evaluateCheck(ctx, check) }(n, check)
	}
	wait.Wait()
	return results, nil
}
func (c CheckEvaluator) evaluateCheck(ctx context.Context, check api.Check) api.CheckResult {

	result := api.CheckResult{CheckID: check.ID, ObservedAt: time.Now().UTC(), Source: "kubernetes-api", Observation: "goal not satisfied"}
	if len(c.Scope.Namespaces) > 0 && !c.Scope.Contains(check.Target) {
		result.Observation = "goal target outside observation scope"
		return result
	}
	target, err := ReadTarget(ctx, c.Reader, check.Target)
	if err != nil {
		result.Observation = "target observation unavailable"
		return result
	}
	if target != nil && len(c.Scope.Namespaces) > 0 && !c.Scope.Matches(check.Target, target) {
		result.Observation = "goal target no longer matches scope"
		return result
	}
	ref := check.Target
	if target != nil {
		ref.UID = string(target.GetUID())
	}
	switch check.Type {
	case "DNS", "TCP", "HTTP":
		result.Source = "owner-probe"
		if c.Probe == nil || check.Vantage != "monitored-pod" || target == nil {
			result.Observation = "required monitored-Pod probe unavailable"
			break
		}
		request := observation.ProbeRequest{Type: check.Type, TimeoutSeconds: 5}
		if check.Type == "HTTP" {
			request.URL = check.Endpoint
		} else if check.Type == "DNS" {
			request.Host = check.Endpoint
		} else {
			var args struct {
				Host string `json:"host"`
				Port int    `json:"port"`
			}
			if json.Unmarshal([]byte(check.Endpoint), &args) != nil {
				result.Observation = "invalid TCP destination"
				break
			}
			request.Host = args.Host
			request.Port = args.Port
		}
		observed, probeErr := c.Probe.Check(ctx, ref, request)
		if probeErr != nil {
			result.Observation = evidence.Bound(evidence.Redact(probeErr.Error()), 1024)
			break
		}
		result.Healthy = observed.Success && observed.Vantage == "pod:"+ref.UID
		result.Source = observed.Vantage
		result.ObservedAt = observed.ObservedAt
		result.Observation = observed.Detail
		result.Fingerprint, _ = api.Hash([]string{ref.UID, check.Endpoint, observed.Vantage})
	case "Prometheus":
		result.Source = "prometheus"
		if c.Metrics == nil {
			result.Observation = "Prometheus observation source unavailable"
			break
		}
		args, _ := json.Marshal(map[string]any{"query": check.Query})
		observed, metricErr := c.Metrics.Call(ctx, c.Scope, observation.ToolCall{ID: check.ID, Name: "query_prometheus", Arguments: args})
		if metricErr != nil || observed.Gap != "" {
			result.Observation = "Prometheus observation incomplete"
			break
		}
		var envelope struct {
			Status string `json:"status"`
			Data   struct {
				ResultType string `json:"resultType"`
				Result     []struct {
					Value []any `json:"value"`
				} `json:"result"`
			} `json:"data"`
		}
		if json.Unmarshal(observed.Content, &envelope) != nil || envelope.Status != "success" || envelope.Data.ResultType != "vector" || len(envelope.Data.Result) == 0 {
			result.Observation = "metric result not a nonempty vector"
			break
		}
		want, ok := check.Expected.(string)
		if !ok {
			result.Observation = "metric expected numeric string required"
			break
		}
		expected, parseErr := strconv.ParseFloat(want, 64)
		if parseErr != nil {
			result.Observation = "invalid metric expectation"
			break
		}
		result.Healthy = true
		observedValues := []string{}
		for _, sample := range envelope.Data.Result {
			if len(sample.Value) != 2 {
				result.Healthy = false
				break
			}
			value, ok := sample.Value[1].(string)
			number, parseErr := strconv.ParseFloat(value, 64)
			if !ok || parseErr != nil || number != expected {
				result.Healthy = false
			}
			if len(observedValues) < 5 {
				observedValues = append(observedValues, fmt.Sprint(sample.Value[1]))
			}
		}
		// The values tell the model how far the metric is from the goal.
		result.Observation = evidence.Bound(evidence.Redact(fmt.Sprintf("metric %s returned %s across %d series, expected %s", check.Query, strings.Join(observedValues, ", "), len(envelope.Data.Result), want)), 1024)
		result.Fingerprint, _ = api.Hash([]string{check.Query, want})
	case "LogSignature":
		result.Source = "pod-logs"
		if target == nil {
			result.Observation = "workload absent"
			break
		}
		if c.Pods == nil {
			result.Observation = "application log evidence unavailable"
			break
		}
		result.Healthy, result.Fingerprint, result.Observation, err = checkLogSignature(ctx, c.Pods, target, check.Query)
		if err != nil {
			result.Healthy = false
			result.Observation = evidence.Bound(evidence.Redact(err.Error()), 1024)
		}
	default:
		verification := api.Verification{Type: check.Type, Path: check.Path, Expected: check.Expected, HealthURL: check.Endpoint}
		result.Healthy, result.Fingerprint, err = CheckResource(target, verification)
		if err != nil {
			result.Observation = evidence.Bound(evidence.Redact(err.Error()), 1024)
			break
		}
		if result.Healthy && check.Type == "ResourceHealthy" && ReferenceKinds(check.Target.Kind) {
			if c.Pods == nil {
				result.Healthy = false
				result.Observation = check.Target.Kind + " reference evidence unavailable"
			} else if result.Healthy, result.Fingerprint, result.Observation, err = CheckReferences(ctx, c.Pods, target); err != nil {
				result.Healthy = false
				result.Observation = evidence.Bound(evidence.Redact(err.Error()), 1024)
			} else {
				result.Observation = evidence.Bound(evidence.Redact(result.Observation), 1024)
			}
		}
		if result.Healthy && (check.Type == "DeploymentRecovery" || check.Type == "ResourceHealthy" && check.Target.Kind == "Deployment") {
			if c.Pods == nil {
				result.Healthy = false
				result.Observation = "Pod ownership evidence unavailable"
			} else {
				result.Healthy, result.Fingerprint, err = CheckPods(ctx, c.Pods, target)
				if err != nil {
					result.Healthy = false
				}
			}
		}
		if result.Healthy {
			result.Healthy = CheckHealth(ctx, verification.HealthURL)
		}
	}
	if result.Healthy {
		result.Observation = "goal satisfied: " + result.Observation
	}
	return result
}

func ChecksHealthy(results []api.CheckResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, r := range results {
		if !r.Healthy {
			return false
		}
	}
	return true
}
func ChecksFingerprint(results []api.CheckResult) string {
	parts := []string{}
	for _, r := range results {
		parts = append(parts, r.CheckID, r.Fingerprint)
	}
	hash, _ := api.Hash(parts)
	return hash
}
