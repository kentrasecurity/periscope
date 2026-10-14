package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/observation"
	"github.com/kentrasecurity/periscope/internal/policy"
	"strings"
	"testing"
)

type toolModel struct{ step int }

func (m *toolModel) Turn(_ context.Context, c llm.Conversation) (llm.TurnResult, error) {
	m.step++
	if m.step == 1 {
		return llm.TurnResult{Calls: []observation.ToolCall{{ID: "read-mode", Name: "get_resource", Arguments: json.RawMessage(`{"apiVersion":"v1","kind":"ConfigMap","namespace":"demo","name":"settings"}`)}}}, nil
	}
	if len(c.Messages) < 3 {
		panic("missing tool response")
	}
	return llm.TurnResult{Decision: &llm.Decision{Diagnosis: "mode broken", Actions: []api.Action{{ID: "fix", Type: "PatchResource", Patch: []api.PatchOp{{Op: "replace", Path: "/data/mode", Value: "healthy"}}}}, EvidenceRefs: []string{"tool-read-mode"}}}, nil
}
func TestToolInvestigationCollectsRequestedEvidenceBeforePlanning(t *testing.T) {
	_, b, _ := setup(t)
	task := b.Tasks["demo/fix"]
	r := observation.NewRegistry(b, policy.Config{Authorization: "RBAC", Namespaces: []string{"demo"}}, 10)
	m := &toolModel{}
	d, err := Investigate(context.Background(), task, r, m)
	if err != nil || m.step != 2 || len(d.Actions) != 1 || task.Status.ModelCalls != 2 || task.Status.ToolCalls != 1 {
		t.Fatalf("investigation failed: %v %+v", err, task.Status)
	}
	if len(task.Status.Evidence) != 1 || task.Status.Evidence[0].ID != "tool-read-mode" {
		t.Fatal("tool evidence not preserved")
	}
}
func TestToolLoopStopsAtBudgetAndDoesNotExecuteModelWrites(t *testing.T) {
	_, b, _ := setup(t)
	task := b.Tasks["demo/fix"]
	task.Spec.Limits.MaxModelCalls = 1
	r := observation.NewRegistry(b, policy.Config{Authorization: "RBAC", Namespaces: []string{"demo"}}, 2)
	_, err := Investigate(context.Background(), task, r, &toolModel{})
	if err == nil || b.Mutations != 0 || task.Status.ModelCalls != 1 {
		t.Fatal("loop escaped read budget")
	}
}

func TestUnavailableEvidenceIsCorrectedWithinExistingBudget(t *testing.T) {
	for _, budget := range []int{1, 2} {
		_, b, _ := setup(t)
		task := b.Tasks["demo/fix"]
		task.Spec.Limits.MaxModelCalls = budget
		task.Status.Evidence = []api.Evidence{{ID: "collected-1", Content: "known observation"}}
		proposal := llm.Decision{Diagnosis: "repair", EvidenceRefs: []string{"invented-1"}, Actions: []api.Action{{ID: "fix", Type: "PatchResource", Patch: []api.PatchOp{{Op: "replace", Path: "/data/mode", Value: "healthy"}}}}}
		corrected := proposal
		corrected.EvidenceRefs = []string{"collected-1"}
		model := &retryToolModel{proposal: proposal, corrected: corrected}
		registry := observation.NewRegistry(b, policy.Config{Authorization: "RBAC", Namespaces: []string{"demo"}}, 2)
		decision, err := Investigate(context.Background(), task, registry, model)
		if budget == 1 && (err == nil || len(decision.Actions) != 0) {
			t.Fatal("ungrounded proposal escaped exhausted budget")
		}
		if budget == 2 && (err != nil || model.calls != 2 || len(decision.EvidenceRefs) != 1 || decision.EvidenceRefs[0] != "collected-1") {
			t.Fatalf("grounding correction failed: calls=%d decision=%+v err=%v", model.calls, decision, err)
		}
		if task.Status.ModelCalls != budget || b.Mutations != 0 {
			t.Fatal("grounding correction bypassed budget or executed writes")
		}
	}
}

// fullEvidenceModel reads once more after the evidence list is full, then
// finishes citing only recorded evidence.
type fullEvidenceModel struct{ step int }

func (m *fullEvidenceModel) Turn(_ context.Context, c llm.Conversation) (llm.TurnResult, error) {
	m.step++
	if m.step == 1 {
		return llm.TurnResult{Calls: []observation.ToolCall{{ID: "late", Name: "get_resource", Arguments: json.RawMessage(`{"apiVersion":"v1","kind":"ConfigMap","namespace":"demo","name":"settings"}`)}}}, nil
	}
	if !strings.Contains(c.Messages[len(c.Messages)-1].Text, "cannot be cited") {
		panic("model not told the late result is not citable")
	}
	return llm.TurnResult{Decision: &llm.Decision{Diagnosis: "diagnosed from earlier evidence", EvidenceRefs: []string{"seed-1"}}}, nil
}

func TestFullEvidenceListDoesNotFailInvestigation(t *testing.T) {
	_, b, _ := setup(t)
	task := b.Tasks["demo/fix"]
	for n := 1; n <= api.MaxEvidenceItems; n++ {
		task.Status.Evidence = append(task.Status.Evidence, api.Evidence{ID: fmt.Sprintf("seed-%d", n), Content: "observation"})
	}
	r := observation.NewRegistry(b, policy.Config{Authorization: "RBAC", Namespaces: []string{"demo"}}, 10)
	d, err := Investigate(context.Background(), task, r, &fullEvidenceModel{})
	if err != nil || d.Diagnosis == "" || len(task.Status.Evidence) != api.MaxEvidenceItems {
		t.Fatalf("full evidence list failed the investigation: %v %+v", err, d)
	}
}

// textThenFinishModel answers in text first, as Claude may with auto tool
// choice, then finishes once corrected.
type textThenFinishModel struct{ seen []llm.Conversation }

func (m *textThenFinishModel) Turn(_ context.Context, c llm.Conversation) (llm.TurnResult, error) {
	m.seen = append(m.seen, c)
	if len(m.seen) == 1 {
		return llm.TurnResult{}, &llm.ProposalError{Reason: "the turn contained no tool call", Proposal: "the mode is wrong", ProviderItems: []json.RawMessage{json.RawMessage(`{"type":"thinking","thinking":"","signature":"s"}`), json.RawMessage(`{"type":"text","text":"the mode is wrong"}`)}}
	}
	return llm.TurnResult{Decision: &llm.Decision{Diagnosis: "mode broken"}}, nil
}

func TestTextAnswerIsReplayedWithItsBlocksAndCorrected(t *testing.T) {
	_, b, _ := setup(t)
	task := b.Tasks["demo/fix"]
	model := &textThenFinishModel{}
	r := observation.NewRegistry(b, policy.Config{Authorization: "RBAC", Namespaces: []string{"demo"}}, 10)
	if _, err := Investigate(context.Background(), task, r, model); err != nil || len(model.seen) != 2 {
		t.Fatalf("text answer not corrected: %v", err)
	}
	replayed := model.seen[1].Messages[1]
	if replayed.Role != "assistant" || len(replayed.ProviderItems) != 2 || !strings.Contains(model.seen[1].Messages[2].Text, "no tool call") {
		t.Fatalf("rejected turn not replayed verbatim before the correction: %+v", model.seen[1].Messages)
	}
}
