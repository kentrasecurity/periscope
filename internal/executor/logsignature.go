package executor

import (
	"context"
	"fmt"
	"strings"

	"github.com/kentrasecurity/periscope/internal/evidence"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

// RecentLogReader reads what a container logged in the last sinceSeconds.
type RecentLogReader interface {
	RecentLogs(ctx context.Context, namespace, pod, container string, sinceSeconds int64) (string, error)
}

const (
	// LogSignatureWindow is how far back application errors are counted; a
	// repair that removes the cause verifies once the window has no matches,
	// even if the Pod was not restarted.
	LogSignatureWindow = 180
	// LogSignatureThreshold matching lines make an application error.
	LogSignatureThreshold = 3
	maxLogPods            = 3
	maxLogContainers      = 4
)

// LogSignatures are application errors with a common Kubernetes-side cause
// (NetworkPolicy, Service, DNS, endpoints, certificates). Matching is
// case-insensitive on substrings.
var LogSignatures = map[string][]string{
	"connection-refused": {"connection refused", "econnrefused"},
	"timeout":            {"i/o timeout", "timed out", "etimedout", "context deadline exceeded"},
	"dns":                {"no such host", "name or service not known", "could not resolve", "temporary failure in name resolution", "nxdomain", "bad address"},
	"unreachable":        {"network is unreachable", "no route to host", "ehostunreach"},
	"tls":                {"x509:", "certificate signed by unknown authority", "certificate has expired"},
}

// LogSignatureMatch is the result of scanning a workload's recent logs.
type LogSignatureMatch struct {
	Signature string
	Lines     int
	Sample    string
}

// ScanLogSignatures counts, per signature, the recent log lines of up to
// three Pods selected by workload u. Only signatures listed in want are
// considered (all when empty); the strongest match is returned.
func ScanLogSignatures(ctx context.Context, r PodReader, logs RecentLogReader, u *unstructured.Unstructured, want ...string) (LogSignatureMatch, error) {
	raw, ok, _ := unstructured.NestedMap(u.Object, "spec", "selector")
	if !ok {
		return LogSignatureMatch{}, fmt.Errorf("workload selector unavailable")
	}
	selector, err := toSelector(raw)
	if err != nil || selector.Empty() {
		return LogSignatureMatch{}, fmt.Errorf("bounded selector required")
	}
	pods, err := r.List(ctx, "v1", "Pod", u.GetNamespace(), selector.String())
	if err != nil {
		return LogSignatureMatch{}, err
	}
	counts, samples := map[string]int{}, map[string]string{}
	scanned := 0
	for _, pod := range pods {
		if scanned >= maxLogPods {
			break
		}
		if pod.GetDeletionTimestamp() != nil || !selector.Matches(labels.Set(pod.GetLabels())) {
			continue
		}
		scanned++
		containers, _, _ := unstructured.NestedSlice(pod.Object, "spec", "containers")
		for n, c := range containers {
			if n >= maxLogContainers {
				break
			}
			name, _ := c.(map[string]any)["name"].(string)
			text, err := logs.RecentLogs(ctx, pod.GetNamespace(), pod.GetName(), name, LogSignatureWindow)
			if err != nil {
				continue // a container that is not running has no recent logs
			}
			for _, line := range strings.Split(text, "\n") {
				lower := strings.ToLower(line)
				for signature, patterns := range LogSignatures {
					if len(want) > 0 && !contains(want, signature) {
						continue
					}
					for _, p := range patterns {
						if strings.Contains(lower, p) {
							counts[signature]++
							if samples[signature] == "" {
								samples[signature] = evidence.Bound(evidence.Redact(strings.TrimSpace(line)), 300)
							}
							break
						}
					}
				}
			}
		}
	}
	best := LogSignatureMatch{}
	for signature, lines := range counts {
		if lines > best.Lines || lines == best.Lines && signature < best.Signature {
			best = LogSignatureMatch{Signature: signature, Lines: lines, Sample: samples[signature]}
		}
	}
	return best, nil
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

// checkLogSignature is healthy while fewer than LogSignatureThreshold recent
// log lines of the workload match the check's signature.
func checkLogSignature(ctx context.Context, r PodReader, target *unstructured.Unstructured, signature string) (bool, string, string, error) {
	logs, ok := r.(RecentLogReader)
	if !ok {
		return false, "", "application log evidence unavailable", nil
	}
	match, err := ScanLogSignatures(ctx, r, logs, target, signature)
	if err != nil {
		return false, "", "", err
	}
	healthy := match.Lines < LogSignatureThreshold
	observation := fmt.Sprintf("%d log line(s) in the last %ds match application error %q", match.Lines, LogSignatureWindow, signature)
	if match.Sample != "" {
		observation += fmt.Sprintf(", e.g. %q", match.Sample)
	}
	return healthy, fmt.Sprintf("%s/%s/%t", target.GetUID(), signature, healthy), observation, nil
}
