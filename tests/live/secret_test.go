//go:build live

package live

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/controller"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// tracingModel logs every proposal and the planner's reply to it.
type tracingModel struct {
	llm.Client
	t *testing.T
}

func (m tracingModel) Turn(ctx context.Context, c llm.Conversation) (llm.TurnResult, error) {
	last := c.Messages[len(c.Messages)-1]
	if last.Role == "user" && len(c.Messages) > 1 {
		m.t.Logf("PLANNER: %.600s", last.Text)
	}
	r, err := m.Client.(llm.ToolClient).Turn(ctx, c)
	if r.Decision != nil {
		raw, _ := json.Marshal(r.Decision.Actions)
		m.t.Logf("PROPOSAL: %.900s", raw)
	}
	var proposal *llm.ProposalError
	if err != nil && errorsAs(err, &proposal) {
		if i := strings.Index(proposal.Proposal, `"actions"`); i >= 0 {
			m.t.Logf("REJECTED ACTIONS: %.1500s", proposal.Proposal[i:])
		}
	}
	return r, err
}

// TestSecretRepairLive reproduces the missing-Secret scenario with
// generated Secret values enabled.
func TestSecretRepairLive(t *testing.T) {
	keyFile := os.Getenv("DOCTOR_API_KEY_FILE")
	if keyFile == "" {
		t.Skip("DOCTOR_API_KEY_FILE not set")
	}
	model, err := llm.New(llm.Config{Provider: "openai", APIKeyFile: keyFile, MaxOutputTokens: 16000})
	if err != nil {
		t.Fatal(err)
	}
	b := testkit.NewMemory()
	if snapshot := os.Getenv("DOCTOR_SNAPSHOT"); snapshot != "" {
		// A `kubectl get -o json` list of the real namespace (no Secrets).
		raw, err := os.ReadFile(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		var list struct{ Items []map[string]any }
		if err := json.Unmarshal(raw, &list); err != nil {
			t.Fatal(err)
		}
		for _, item := range list.Items {
			u := &unstructured.Unstructured{Object: item}
			if u.GetKind() == "Event" {
				u.SetName(u.GetName() + "-event")
			}
			if u.GetKind() == "Service" || u.GetKind() == "ConfigMap" || u.GetKind() == "PersistentVolumeClaim" {
				u.SetName(u.GetName() + "-" + strings.ToLower(u.GetKind()))
			}
			b.PutResource(u)
		}
	}
	labels := map[string]any{"app.kubernetes.io/name": "suite-secret"}
	container := map[string]any{"name": "api", "image": "busybox:1.36", "command": []any{"sh", "-c", "exec sleep 360000"},
		"env": []any{map[string]any{"name": "DB_PASSWORD", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "db-credentials", "key": "password"}}}}}
	if os.Getenv("DOCTOR_SNAPSHOT") == "" {
		b.PutResource(testkit.Resource("apps/v1", "Deployment", ns, "suite-secret", "dep-uid", map[string]any{"spec": map[string]any{"replicas": int64(1), "selector": map[string]any{"matchLabels": labels}, "template": map[string]any{"metadata": map[string]any{"labels": labels}, "spec": map[string]any{"containers": []any{container}}}},
			"status": map[string]any{"observedGeneration": int64(1), "replicas": int64(1), "updatedReplicas": int64(1), "readyReplicas": int64(0), "availableReplicas": int64(0)}}))
		b.PutResource(testkit.Resource("v1", "Event", ns, "ev", "ev-uid", map[string]any{"type": "Warning", "reason": "Failed", "message": `Error: secret "db-credentials" not found`, "involvedObject": map[string]any{"kind": "Deployment", "name": "suite-secret", "uid": "dep-uid"}}))
	}
	grace := 0
	task := b.PutTask(ns, "doctor", "doctor-uid", api.TaskSpec{Mode: "Automatic", Scope: &api.Scope{Namespaces: []string{ns}, Resources: []api.ResourceSelector{{LabelSelector: "periscope.kentrasecurity.io/healing-protected!=true"}}}, Objective: "Keep the application workloads in this namespace healthy with the smallest change.",
		Monitoring: &api.Monitoring{IntervalSeconds: 30, GracePeriodSeconds: &grace}, Limits: api.Limits{DeadlineSeconds: 600, MaxModelCalls: 12, MaxToolCalls: 60}})
	task.Object.SetGeneration(1)
	p := policy.Config{Authorization: "RBAC", CoordinationNamespace: ns, Namespaces: []string{ns}, Repairs: policy.Repairs{Secrets: policy.SecretRepairs{Create: "generate"}}}
	checker := executor.CheckEvaluator{Reader: b, Pods: b}
	inv := &controller.Investigator{Backend: b, Model: tracingModel{model, t}, Policy: p, Checker: checker, Collector: evidence.Collector{Reader: b, Policy: p, MaxToolCalls: 30}}
	if err := inv.Reconcile(context.Background(), ns, "doctor"); err != nil {
		t.Fatal(err)
	}
	t.Logf("PHASE %s REPORT %.800s", task.Status.Phase, task.Status.Report)
	for _, c := range task.Status.Conditions {
		t.Logf("CONDITION %s: %.800s", c.Reason, c.Message)
	}
	if !strings.Contains(task.Status.Phase, "Awaiting") && task.Status.PlanRef == nil {
		t.Fatalf("no plan for the missing Secret")
	}
}

func errorsAs(err error, target **llm.ProposalError) bool {
	for err != nil {
		if p, ok := err.(*llm.ProposalError); ok {
			*target = p
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
