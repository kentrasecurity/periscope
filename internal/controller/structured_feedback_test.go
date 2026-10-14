package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/observation"
	"github.com/kentrasecurity/periscope/internal/policy"
)

func TestMalformedNativeFinishCanBeCorrectedWithoutWrites(t *testing.T) {
	for _, budget := range []int{1, 2} {
		_, b, _ := setup(t)
		task := b.Tasks["demo/fix"]
		task.Spec.Limits.MaxModelCalls = budget
		task.Status.Evidence = []api.Evidence{{ID: "known", Content: "mode broken"}}
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			var payload map[string]any
			json.NewDecoder(r.Body).Decode(&payload)
			if calls > 1 {
				raw, _ := json.Marshal(payload["messages"])
				if !strings.Contains(string(raw), "Planner rejected") {
					t.Error("missing corrective feedback")
				}
				if strings.Contains(string(raw), "fake-test-credential") {
					t.Error("provider credential leaked into corrective conversation")
				}
			}
			decision := map[string]any{"diagnosis": "repair", "risk": "low", "actions": []any{map[string]any{"id": "fix", "type": "PatchResource", "patch": []any{map[string]any{"op": "replace", "path": "/data/mode", "value": "healthy"}}}}, "verification": map[string]any{"type": "FieldEquals", "path": "/data/mode", "expected": "healthy", "timeoutSeconds": 60, "stableWindowSeconds": 1}, "evidenceRefs": []string{"known"}}
			if calls == 1 {
				decision["fake-test-credential"] = true
			}
			arguments, _ := json.Marshal(decision)
			json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"tool_calls": []any{map[string]any{"id": "finish", "type": "function", "function": map[string]any{"name": "finish_plan", "arguments": string(arguments)}}}}}}})
		}))
		keyFile := t.TempDir() + "/key"
		if err := os.WriteFile(keyFile, []byte("fake-test-credential"), 0600); err != nil {
			t.Fatal(err)
		}
		client, err := llm.New(llm.Config{Provider: "openai", BaseURL: server.URL, Model: "test", APIKeyFile: keyFile, AllowHTTPForTests: true, Timeout: time.Second, MaxResponseBytes: 65536, MaxOutputTokens: 1024})
		if err != nil {
			t.Fatal(err)
		}
		registry := observation.NewRegistry(b, policy.Config{Authorization: "RBAC", Namespaces: []string{"demo"}}, 2)
		d, err := Investigate(context.Background(), task, registry, client.(llm.ToolClient))
		server.Close()
		if budget == 1 && (err == nil || len(d.Actions) != 0) {
			t.Fatal("malformed decision escaped budget")
		}
		if budget == 2 && (err != nil || calls != 2 || len(d.Actions) != 1) {
			t.Fatalf("native correction failed: calls=%d err=%v", calls, err)
		}
		if task.Status.ModelCalls != budget || b.Mutations != 0 {
			t.Fatal("correction bypassed budget or executed writes")
		}
	}
}
