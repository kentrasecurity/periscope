// Package api defines the immutable authorization contracts shared by all components.
package api

import (
	"fmt"
	"strings"
	"time"
)

const (
	Group               = "periscope.kentrasecurity.io"
	Version             = "v1alpha1"
	MaxActions          = 10
	MaxEvidenceItems    = 32
	MaxEvidenceBytes    = 256 * 1024
	MaxLogBytes         = 64 * 1024
	OperationAnnotation = Group + "/operation"
)

type ObjectRef struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

type TargetRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
}

type Limits struct {
	DeadlineSeconds int `json:"deadlineSeconds"`
	MaxModelCalls   int `json:"maxModelCalls"`
	MaxToolCalls    int `json:"maxToolCalls"`
}

func DefaultLimits() Limits { return Limits{DeadlineSeconds: 600, MaxModelCalls: 5, MaxToolCalls: 30} }

type Monitoring struct {
	IntervalSeconds int `json:"intervalSeconds"`
	// GracePeriodSeconds is how long a resource must stay unhealthy before it
	// becomes an incident, so rollouts and starting Pods cost no inference.
	GracePeriodSeconds *int `json:"gracePeriodSeconds,omitempty"`
}

const DefaultGracePeriodSeconds = 60

// GracePeriod returns the task's failure grace period.
func (t TaskSpec) GracePeriod() time.Duration {
	if t.Monitoring != nil && t.Monitoring.GracePeriodSeconds != nil {
		return time.Duration(*t.Monitoring.GracePeriodSeconds) * time.Second
	}
	return DefaultGracePeriodSeconds * time.Second
}

// Suspect is an unhealthy resource still inside the grace period.
type Suspect struct {
	Target TargetRef `json:"target"`
	Since  time.Time `json:"since"`
}

// OperatorLabel marks the operator's own workloads. Discovery never reports
// them and no plan may target them, so an agent never repairs itself.
const (
	OperatorLabel      = "app.kubernetes.io/part-of"
	OperatorLabelValue = "periscope"
)

func IsOperatorInfrastructure(labels map[string]string) bool {
	return labels[OperatorLabel] == OperatorLabelValue
}

type TaskSpec struct {
	HealingLimits *HealingLimits `json:"healingLimits,omitempty"`
	Monitoring    *Monitoring    `json:"monitoring,omitempty"`
	Checks        []Check        `json:"checks,omitempty"`
	Scope         *Scope         `json:"scope,omitempty"`
	Suspend       bool           `json:"suspend,omitempty"`
	Verification  *Verification  `json:"verification,omitempty"`
	TargetRef     TargetRef      `json:"targetRef,omitempty,omitzero"`
	Mode          string         `json:"mode"`
	Objective     string         `json:"objective"`
	PolicyRef     string         `json:"policyRef,omitempty"`
	Limits        Limits         `json:"limits"`
}

type Condition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason"`
	Message            string    `json:"message"`
	ObservedGeneration int64     `json:"observedGeneration"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
}

// MaxConditions bounds condition history below the CRD limit (32), so a
// long-running task can always save status.
const MaxConditions = 16

// AppendConditions appends conditions and keeps the newest MaxConditions.
func AppendConditions(existing []Condition, added ...Condition) []Condition {
	out := append(append([]Condition(nil), existing...), added...)
	if len(out) > MaxConditions {
		out = out[len(out)-MaxConditions:]
	}
	return out
}

type Evidence struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	CollectedAt time.Time `json:"collectedAt"`
	Hash        string    `json:"hash"`
	Content     string    `json:"content"`
}

type TaskStatus struct {
	ScopeScanCursor     int              `json:"scopeScanCursor,omitempty"`
	LastScopeScanAt     *time.Time       `json:"lastScopeScanAt,omitempty"`
	Budget              BudgetStatus     `json:"budget,omitempty,omitzero"`
	Suspects            []Suspect        `json:"suspects,omitempty"`
	PendingIncidents    []IncidentStatus `json:"pendingIncidents,omitempty"`
	IncidentHistory     []IncidentStatus `json:"incidentHistory,omitempty"`
	Incident            *IncidentStatus  `json:"incident,omitempty"`
	ApprovalRef         *ObjectRef       `json:"approvalRef,omitempty"`
	Cycle               int64            `json:"cycle,omitempty"`
	LastCheckedAt       *time.Time       `json:"lastCheckedAt,omitempty"`
	Healthy             *bool            `json:"healthy,omitempty"`
	MonitorDigest       string           `json:"monitorDigest,omitempty"`
	MonitorUID          string           `json:"monitorUID,omitempty"`
	MonitorStableSince  *time.Time       `json:"monitorStableSince,omitempty"`
	MonitorVerification *Verification    `json:"monitorVerification,omitempty"`
	MonitorFingerprint  string           `json:"monitorFingerprint,omitempty"`
	ObservedGeneration  int64            `json:"observedGeneration"`
	Phase               string           `json:"phase"`
	TargetUID           string           `json:"targetUID,omitempty"`
	Attempt             int              `json:"attempt,omitempty"`
	ModelCalls          int              `json:"modelCalls,omitempty"`
	ToolCalls           int              `json:"toolCalls,omitempty"`
	PlanRef             *ObjectRef       `json:"planRef,omitempty"`
	Report              string           `json:"report,omitempty"`
	Evidence            []Evidence       `json:"evidence,omitempty"`
	Gaps                []string         `json:"gaps,omitempty"`
	Conditions          []Condition      `json:"conditions,omitempty"`
	StartedAt           *time.Time       `json:"startedAt,omitempty"`
	CompletedAt         *time.Time       `json:"completedAt,omitempty"`
}

type PatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

type Action struct {
	BindingID string         `json:"bindingID,omitempty"`
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Target    TargetRef      `json:"target,omitempty"`
	Patch     []PatchOp      `json:"patch,omitempty"`
	Object    map[string]any `json:"object,omitempty"`
	// SecretSources fills the keys of a created Secret at execution, so plans
	// never carry credential values.
	SecretSources map[string]SecretSource `json:"secretSources,omitempty"`
}

// SecretSource is either Generate random bytes or a copy of FromKey in the
// owner-allowed Secret FromSecret.
type SecretSource struct {
	Generate   int    `json:"generate,omitempty"`
	FromSecret string `json:"fromSecret,omitempty"`
	FromKey    string `json:"fromKey,omitempty"`
}

type Preconditions struct {
	SpecDigest string `json:"specDigest"`
}

type Verification struct {
	Type                string `json:"type"`
	TimeoutSeconds      int    `json:"timeoutSeconds"`
	StableWindowSeconds int    `json:"stableWindowSeconds"`
	Path                string `json:"path,omitempty"`
	Expected            any    `json:"expected,omitempty"`
	HealthURL           string `json:"healthURL,omitempty"`
}

type TargetBinding struct {
	ID            string        `json:"id"`
	Target        TargetRef     `json:"target"`
	Preconditions Preconditions `json:"preconditions"`
	AfterActionID string        `json:"afterActionID,omitempty"`
}

type PlanSpec struct {
	Checks               []Check         `json:"checks,omitempty"`
	Targets              []TargetBinding `json:"targets,omitempty"`
	IncidentID           string          `json:"incidentID,omitempty"`
	OriginalChecksDigest string          `json:"originalChecksDigest,omitempty"`
	TaskCycle            int64           `json:"taskCycle,omitempty"`
	TaskRef              ObjectRef       `json:"taskRef"`
	TaskGeneration       int64           `json:"taskGeneration"`
	TargetRef            TargetRef       `json:"targetRef"`
	Preconditions        Preconditions   `json:"preconditions"`
	PolicyDigest         string          `json:"policyDigest"`
	Diagnosis            string          `json:"diagnosis"`
	Risk                 string          `json:"risk"`
	Actions              []Action        `json:"actions"`
	Verification         Verification    `json:"verification"`
	Evidence             []Evidence      `json:"evidence,omitempty"`
	Digest               string          `json:"digest"`
}

type JournalEntry struct {
	ID                 string    `json:"id"`
	State              string    `json:"state"`
	Operation          string    `json:"operation"`
	BeforeDigest       string    `json:"beforeDigest"`
	AfterDigest        string    `json:"afterDigest,omitempty"`
	ResultUID          string    `json:"resultUID,omitempty"`
	ServerResultDigest string    `json:"serverResultDigest,omitempty"`
	UpdatedAt          time.Time `json:"updatedAt"`
	Error              string    `json:"error,omitempty"`
}

type PlanStatus struct {
	CheckResults            []CheckResult  `json:"checkResults,omitempty"`
	Phase                   string         `json:"phase,omitempty"`
	ApprovalUID             string         `json:"approvalUID,omitempty"`
	Entries                 []JournalEntry `json:"entries,omitempty"`
	Conditions              []Condition    `json:"conditions,omitempty"`
	StableSince             *time.Time     `json:"stableSince,omitempty"`
	VerificationFingerprint string         `json:"verificationFingerprint,omitempty"`
	ExecutionStartedAt      *time.Time     `json:"executionStartedAt,omitempty"`
}

type ApprovalSpec struct {
	PlanName   string    `json:"planName,omitempty"`
	Decision   string    `json:"decision,omitempty"`
	TaskUID    string    `json:"taskUID"`
	PlanUID    string    `json:"planUID"`
	PlanDigest string    `json:"planDigest"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// Automatic explicitly authorizes checked approvals; evidence cannot change mode.
func ValidateTask(t TaskSpec) error {
	if t.Verification != nil {
		v := t.Verification
		if v.TimeoutSeconds < 1 || v.TimeoutSeconds > 1800 || v.StableWindowSeconds < 1 || v.StableWindowSeconds > 600 || v.StableWindowSeconds > v.TimeoutSeconds || v.HealthURL != "" {
			return fmt.Errorf("invalid task verification bounds or model-selected health URL")
		}
		switch v.Type {
		case "DeploymentRecovery", "PodRecovery", "ResourceHealthy", "FieldEquals", "ResourceExists", "ResourceAbsent":
		default:
			return fmt.Errorf("unsupported task verification")
		}
	}
	if t.HealingLimits != nil {
		if err := t.HealingLimits.Validate(); err != nil {
			return err
		}
	}
	if err := ValidateChecks(t); err != nil {
		return err
	}
	switch t.Mode {
	case "Observe", "Propose", "HumanApproved", "Automatic":
	default:
		return fmt.Errorf("unsupported task mode %q", t.Mode)
	}
	if t.Monitoring != nil && (t.Monitoring.IntervalSeconds < 5 || t.Monitoring.IntervalSeconds > 3600) {
		return fmt.Errorf("monitoring interval outside bounds")
	}
	if t.Monitoring != nil && t.Monitoring.GracePeriodSeconds != nil && (*t.Monitoring.GracePeriodSeconds < 0 || *t.Monitoring.GracePeriodSeconds > 3600) {
		return fmt.Errorf("monitoring grace period outside bounds")
	}
	if t.Scope != nil {
		if t.TargetRef.APIVersion != "" || t.TargetRef.Kind != "" || t.TargetRef.Name != "" || t.TargetRef.Namespace != "" || t.TargetRef.UID != "" {
			return fmt.Errorf("choose targetRef or scope")
		}
		if err := t.Scope.Validate(); err != nil {
			return err
		}
	} else if t.TargetRef.APIVersion == "" || t.TargetRef.Kind == "" || t.TargetRef.Name == "" {
		return fmt.Errorf("target apiVersion, kind and name are required")
	}
	if strings.TrimSpace(t.Objective) == "" || len(t.Objective) > 8192 {
		return fmt.Errorf("objective must contain 1..8192 bytes")
	}
	if t.Limits.DeadlineSeconds < 1 || t.Limits.DeadlineSeconds > 3600 || t.Limits.MaxModelCalls < 1 || t.Limits.MaxModelCalls > 20 || t.Limits.MaxToolCalls < 1 || t.Limits.MaxToolCalls > 100 {
		return fmt.Errorf("task limits outside permitted bounds")
	}
	return nil
}
