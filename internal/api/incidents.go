package api

import (
	"fmt"
	"time"
)

type Check struct {
	TimeoutSeconds      int       `json:"timeoutSeconds,omitempty"`
	StableWindowSeconds int       `json:"stableWindowSeconds,omitempty"`
	ID                  string    `json:"id"`
	Type                string    `json:"type"`
	Target              TargetRef `json:"target"`
	Path                string    `json:"path,omitempty"`
	Expected            any       `json:"expected,omitempty"`
	Source              string    `json:"source,omitempty"`
	Query               string    `json:"query,omitempty"`
	Endpoint            string    `json:"endpoint,omitempty"`
	Vantage             string    `json:"vantage,omitempty"`
}
type CheckResult struct {
	CheckID     string    `json:"checkID"`
	Healthy     bool      `json:"healthy"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Observation string    `json:"observation"`
	ObservedAt  time.Time `json:"observedAt"`
	Source      string    `json:"source"`
}
type IncidentStatus struct {
	ID                   string      `json:"id"`
	Target               TargetRef   `json:"target"`
	Attempt              int         `json:"attempt"`
	OriginalChecks       []Check     `json:"originalChecks"`
	OriginalChecksDigest string      `json:"originalChecksDigest"`
	FailureFingerprint   string      `json:"failureFingerprint,omitempty"`
	NextAttemptAt        *time.Time  `json:"nextAttemptAt,omitempty"`
	PriorPlanRefs        []ObjectRef `json:"priorPlanRefs,omitempty"`
	// Diagnosis is the model's explanation: the read-only diagnosis in Observe
	// mode, or why no safe repair exists when Outcome is NoSafeAction.
	Diagnosis string `json:"diagnosis,omitempty"`
	// Outcome NoSafeAction or RepairFailed holds the incident for owner action:
	// it is not investigated again until its failure changes.
	Outcome string `json:"outcome,omitempty"`
}

const (
	IncidentNoSafeAction = "NoSafeAction"
	// IncidentRepairFailed holds an incident whose repair failed in a way a new
	// investigation cannot fix; Diagnosis carries the failure.
	IncidentRepairFailed = "RepairFailed"
)

func VerificationCheck(target TargetRef, v Verification) Check {
	target.UID = ""
	return Check{TimeoutSeconds: v.TimeoutSeconds, StableWindowSeconds: v.StableWindowSeconds, ID: "recovery", Type: v.Type, Target: target, Path: v.Path, Expected: v.Expected, Endpoint: v.HealthURL}
}

func ValidateChecks(t TaskSpec) error {
	if len(t.Checks) > 32 {
		return fmt.Errorf("too many goal checks")
	}
	ids := map[string]bool{}
	for _, c := range t.Checks {
		if c.ID == "" || len(c.ID) > 128 || ids[c.ID] || c.Target.Namespace == "" || c.Target.Name == "" || c.Target.APIVersion == "" || c.Target.Kind == "" {
			return fmt.Errorf("invalid explicit check identity")
		}
		ids[c.ID] = true
		if t.Scope != nil && !t.Scope.Contains(c.Target) {
			return fmt.Errorf("check outside task scope")
		}
		if t.Scope == nil {
			ref := t.TargetRef
			if ref.Namespace == "" {
				ref.Namespace = c.Target.Namespace
			}
			if ResourceKey(ref) != ResourceKey(c.Target) {
				return fmt.Errorf("target checks require same exact resource")
			}
		}
		if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 1800 || c.StableWindowSeconds < 1 || c.StableWindowSeconds > 600 || c.StableWindowSeconds > c.TimeoutSeconds {
			return fmt.Errorf("invalid goal check timing")
		}
		switch c.Type {
		case "DNS", "TCP", "HTTP":
			if c.Target.Kind != "Pod" || c.Target.APIVersion != "v1" || c.Vantage != "monitored-pod" || c.Endpoint == "" {
				return fmt.Errorf("network check needs explicit destination and monitored Pod")
			}
		case "Prometheus":
			if c.Query == "" || len(c.Query) > 8192 {
				return fmt.Errorf("explicit bounded metric query required")
			}
			if _, ok := c.Expected.(string); !ok {
				return fmt.Errorf("metric equality needs numeric string expectation")
			}
		case "LogSignature":
			if c.Query == "" || len(c.Query) > 64 || c.Target.Kind != "Deployment" && c.Target.Kind != "StatefulSet" && c.Target.Kind != "DaemonSet" {
				return fmt.Errorf("log signature check needs a signature and a workload target")
			}
		case "PodRecovery", "DeploymentRecovery", "ResourceHealthy", "ResourceExists", "ResourceAbsent", "FieldEquals":
		default:
			return fmt.Errorf("unsupported check type")
		}
	}
	return nil
}
