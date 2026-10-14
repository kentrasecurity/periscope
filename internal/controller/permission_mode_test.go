package controller

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/observation"
	"github.com/kentrasecurity/periscope/internal/policy"
)

type permissionModeModel struct{ t *testing.T }

func (m permissionModeModel) Turn(_ context.Context, c llm.Conversation) (llm.TurnResult, error) {
	var input map[string]any
	if err := json.Unmarshal([]byte(evidence.Redact(c.Messages[0].Text)), &input); err != nil {
		m.t.Fatal(err)
	}
	if input["permissionMode"] != "RBAC" {
		m.t.Error("non-secret permission mode was absent or redacted")
	}
	return llm.TurnResult{Decision: &llm.Decision{Diagnosis: "fixture inspection"}}, nil
}
func TestNativePermissionModeSurvivesCredentialRedaction(t *testing.T) {
	_, backend, _ := setup(t)
	task := backend.Tasks["demo/fix"]
	registry := observation.NewRegistry(backend, policy.Config{Authorization: "RBAC", Namespaces: []string{"demo"}}, 2)
	if _, err := Investigate(context.Background(), task, registry, permissionModeModel{t: t}); err != nil {
		t.Fatal(err)
	}
	if backend.Mutations != 0 {
		t.Fatal("metadata regression executed writes")
	}
}
