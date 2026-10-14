package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kentrasecurity/periscope/internal/observation"
)

func TestResponsesToolContinuationKeepsReasoningAndRedactsEvidence(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/responses" {
			t.Errorf("wrong endpoint: %s", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(body)
		if strings.Contains(string(encoded), "credential-canary") {
			t.Error("credential-like evidence escaped Responses redaction")
		}
		if body["store"] != false || body["reasoning"].(map[string]any)["effort"] != "medium" {
			t.Error("missing stateless reasoning settings")
		}
		if calls == 1 {
			w.Write([]byte(`{"status":"completed","output":[{"type":"reasoning","id":"rs_one","summary":[],"encrypted_content":"opaque-reasoning"},{"type":"function_call","id":"fc_one","call_id":"read-one","name":"get_resource","arguments":"{\"name\":\"app\"}","status":"completed"}]}`))
		} else {
			input := body["input"].([]any)
			foundReasoning, foundResult := false, false
			for _, raw := range input {
				item := raw.(map[string]any)
				if item["type"] == "reasoning" && item["encrypted_content"] == "opaque-reasoning" {
					foundReasoning = true
				}
				if item["type"] == "function_call_output" && item["call_id"] == "read-one" {
					foundResult = true
				}
			}
			if !foundReasoning || !foundResult {
				t.Error("lost tool continuation or encrypted reasoning")
			}
			json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": []any{map[string]any{"type": "function_call", "call_id": "finish-one", "name": "finish_plan", "arguments": decisionJSON, "status": "completed"}}})
		}
	}))
	defer server.Close()
	p := &provider{config: Config{Provider: "openai", BaseURL: server.URL, Model: "gpt-6-luna", MaxOutputTokens: 4096, MaxResponseBytes: 65536}, key: "fake", http: server.Client()}
	// Exercise the explicitly selected Responses transport.
	p.config.API, p.config.ReasoningEffort = "responses", "medium"
	c := Conversation{Messages: []Message{{Role: "user", Text: "investigate access_token=credential-canary"}}, Tools: []observation.ToolDefinition{{Name: "get_resource", Schema: json.RawMessage(`{"type":"object"}`)}}}
	result, err := p.Turn(context.Background(), c)
	if err != nil || len(result.Calls) != 1 {
		t.Fatalf("Responses read turn failed: %+v %v", result, err)
	}
	assistant := Message{Role: "assistant", ToolCalls: result.Calls, ProviderItems: result.ProviderItems}
	c.Messages = append(c.Messages, assistant, Message{Role: "tool", ToolCallID: "read-one", Text: "resource observed"})
	final, err := p.Turn(context.Background(), c)
	if err != nil || final.Decision == nil {
		t.Fatalf("Responses finish failed: %+v %v", final, err)
	}
}

func TestResponsesIncompleteTurnCannotProduceActions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"incomplete","output":[{"type":"function_call","call_id":"finish","name":"finish_plan","arguments":"{}","status":"completed"}]}`))
	}))
	defer server.Close()
	p := &provider{config: Config{Provider: "openai", BaseURL: server.URL, Model: "gpt-6-luna", MaxOutputTokens: 4096, MaxResponseBytes: 65536}, key: "fake", http: server.Client()}
	p.config.API, p.config.ReasoningEffort = "responses", "medium"
	result, err := p.Turn(context.Background(), Conversation{Messages: []Message{{Role: "user", Text: "inspect"}}})
	if err == nil || result.Decision != nil || len(result.Calls) > 0 {
		t.Fatal("incomplete Responses turn escaped")
	}
}
