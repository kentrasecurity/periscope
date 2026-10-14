package llm

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kentrasecurity/periscope/internal/observation"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProviderNativeToolRoundTrips(t *testing.T) {
	for _, providerName := range []string{"openai", "anthropic"} {
		t.Run(providerName, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload map[string]any
				json.NewDecoder(r.Body).Decode(&payload)
				if providerName == "openai" && payload["tool_choice"] != "required" {
					t.Error("tool-only parser requires a tool-only response contract")
				}
				// Claude 5.5 models reject forced tool choice; text answers are corrected instead.
				if choice, _ := payload["tool_choice"].(map[string]any); providerName == "anthropic" && (choice == nil || choice["type"] != "auto") {
					t.Error("Anthropic requests must use tool_choice auto")
				}
				if len(payload["tools"].([]any)) != 2 {
					t.Error("tool definitions missing")
				}
				w.Header().Set("Content-Type", "application/json")
				if providerName == "openai" {
					w.Write([]byte(`{"choices":[{"finish_reason":"tool_calls","message":{"tool_calls":[{"id":"read-1","type":"function","function":{"name":"get_resource","arguments":"{\"name\":\"app\"}"}}]}}]}`))
				} else {
					w.Write([]byte(`{"stop_reason":"tool_use","content":[{"type":"tool_use","id":"read-1","name":"get_resource","input":{"name":"app"}}]}`))
				}
			}))
			defer server.Close()
			p := &provider{config: Config{Provider: providerName, BaseURL: server.URL, Model: "test", MaxOutputTokens: 1024, MaxResponseBytes: 65536}, key: "fake", http: server.Client()}
			result, err := p.Turn(context.Background(), Conversation{Messages: []Message{{Role: "user", Text: "investigate"}}, Tools: []observation.ToolDefinition{{Name: "get_resource", Schema: json.RawMessage(`{"type":"object"}`)}}})
			if err != nil || len(result.Calls) != 1 || result.Calls[0].ID != "read-1" {
				t.Fatalf("native tool parsing failed: %+v %v", result, err)
			}
		})
	}
}

func TestNativeConversationRedactionPreservesJSON(t *testing.T) {
	for _, name := range []string{"openai", "anthropic"} {
		t.Run(name, func(t *testing.T) {
			called := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(payload)
				if strings.Contains(string(raw), "credential-canary") {
					t.Error("credential-like evidence escaped redaction")
				}
				if name == "openai" {
					json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"tool_calls": []any{map[string]any{"id": "finish", "type": "function", "function": map[string]any{"name": "finish_plan", "arguments": decisionJSON}}}}}}})
				} else {
					var d any
					json.Unmarshal([]byte(decisionJSON), &d)
					json.NewEncoder(w).Encode(map[string]any{"stop_reason": "tool_use", "content": []any{map[string]any{"type": "tool_use", "id": "finish", "name": "finish_plan", "input": d}}})
				}
			}))
			defer server.Close()
			p := &provider{config: Config{Provider: name, BaseURL: server.URL, Model: "test", MaxOutputTokens: 1024, MaxResponseBytes: 65536}, key: "fake", http: server.Client()}
			_, err := p.Turn(context.Background(), Conversation{Messages: []Message{{Role: "user", Text: `Evidence includes access_token=credential-canary and nested "password":"credential-canary"`}}})
			if err != nil || !called {
				t.Fatalf("redaction broke native conversation: %v", err)
			}
		})
	}
}

func TestTransientProviderErrorsAreRetried(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"stop_reason":"tool_use","content":[{"type":"tool_use","id":"read-1","name":"get_resource","input":{}}]}`))
	}))
	defer server.Close()
	p := &provider{config: Config{Provider: "anthropic", BaseURL: server.URL, Model: "test", MaxOutputTokens: 1024, MaxResponseBytes: 65536}, key: "fake", http: server.Client()}
	result, err := p.Turn(context.Background(), Conversation{Messages: []Message{{Role: "user", Text: "investigate"}}, Tools: []observation.ToolDefinition{{Name: "get_resource", Schema: json.RawMessage(`{"type":"object"}`)}}})
	if err != nil || len(result.Calls) != 1 || calls != 3 {
		t.Fatalf("rate limit was not retried: calls=%d %v", calls, err)
	}
	calls = -10
	if _, err = p.Turn(context.Background(), Conversation{Messages: []Message{{Role: "user", Text: "investigate"}}}); err == nil || calls != -10+maxProviderRetries+1 {
		t.Fatalf("persistent rate limit not bounded: calls=%d %v", calls, err)
	}
}

func TestProviderErrorMessageIsReported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"Your credit balance is too low (key fake-key-canary)"}}`))
	}))
	defer server.Close()
	p := &provider{config: Config{Provider: "anthropic", BaseURL: server.URL, Model: "test", MaxOutputTokens: 1024, MaxResponseBytes: 65536}, key: "fake-key-canary", http: server.Client()}
	_, err := p.Turn(context.Background(), Conversation{Messages: []Message{{Role: "user", Text: "investigate"}}})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400: invalid_request_error: Your credit balance is too low") {
		t.Fatalf("provider explanation lost: %v", err)
	}
	if strings.Contains(err.Error(), "fake-key-canary") {
		t.Fatal("provider key echoed in error")
	}
}

func TestAnthropicGroupsToolResultsAndCachesPrefix(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		w.Write([]byte(`{"stop_reason":"tool_use","content":[{"type":"tool_use","id":"read-3","name":"get_resource","input":{}}]}`))
	}))
	defer server.Close()
	p := &provider{config: Config{Provider: "anthropic", BaseURL: server.URL, Model: "test", MaxOutputTokens: 1024, MaxResponseBytes: 65536}, key: "fake", http: server.Client()}
	calls := []observation.ToolCall{{ID: "read-1", Name: "get_resource", Arguments: json.RawMessage(`{}`)}, {ID: "read-2", Name: "get_resource", Arguments: json.RawMessage(`{}`)}}
	conversation := Conversation{Tools: []observation.ToolDefinition{{Name: "get_resource", Schema: json.RawMessage(`{"type":"object"}`)}}, Messages: []Message{
		{Role: "user", Text: "investigate"},
		{Role: "assistant", ToolCalls: calls},
		{Role: "tool", ToolCallID: "read-1", Text: "one"},
		{Role: "tool", ToolCallID: "read-2", Text: "two"},
	}}
	if _, err := p.Turn(context.Background(), conversation); err != nil {
		t.Fatal(err)
	}
	messages := payload["messages"].([]any)
	if len(messages) != 3 {
		t.Fatalf("tool results must share one user turn, got %d turns", len(messages))
	}
	results := messages[2].(map[string]any)["content"].([]any)
	if messages[2].(map[string]any)["role"] != "user" || len(results) != 2 {
		t.Fatalf("unexpected tool result turn: %v", messages[2])
	}
	if results[1].(map[string]any)["cache_control"] == nil {
		t.Fatal("latest turn not marked for prompt caching")
	}
	system := payload["system"].([]any)
	if system[0].(map[string]any)["cache_control"] == nil {
		t.Fatal("system prompt not marked for prompt caching")
	}
}

func TestMixedFinishAndReadIsCorrectable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var d any
		json.Unmarshal([]byte(decisionJSON), &d)
		json.NewEncoder(w).Encode(map[string]any{"stop_reason": "tool_use", "content": []any{
			map[string]any{"type": "tool_use", "id": "read-1", "name": "get_resource", "input": map[string]any{}},
			map[string]any{"type": "tool_use", "id": "finish", "name": "finish_plan", "input": d},
		}})
	}))
	defer server.Close()
	p := &provider{config: Config{Provider: "anthropic", BaseURL: server.URL, Model: "test", MaxOutputTokens: 1024, MaxResponseBytes: 65536}, key: "fake", http: server.Client()}
	_, err := p.Turn(context.Background(), Conversation{Messages: []Message{{Role: "user", Text: "investigate"}}, Tools: []observation.ToolDefinition{{Name: "get_resource", Schema: json.RawMessage(`{"type":"object"}`)}}})
	var proposal *ProposalError
	if !errors.As(err, &proposal) {
		t.Fatalf("mixed finish/read turn should be correctable, got %v", err)
	}
}

func TestDefaultModelPerProvider(t *testing.T) {
	if DefaultModel("anthropic") != "claude-opus-5-5" || DefaultModel("openai") != "gpt-6-luna" {
		t.Fatal("unexpected provider defaults")
	}
}

// claudeServer records each request and answers with the next scripted response.
func claudeServer(t *testing.T, responses ...string) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	requests := &[]map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		*requests = append(*requests, payload)
		w.Write([]byte(responses[(len(*requests)-1)%len(responses)]))
	}))
	t.Cleanup(server.Close)
	return server, requests
}

func claudeProvider(url string) *provider {
	return &provider{config: Config{Provider: "anthropic", BaseURL: url, Model: "claude-opus-5-5", MaxOutputTokens: 16000, MaxResponseBytes: 65536}, key: "fake", http: http.DefaultClient}
}

var readTool = []observation.ToolDefinition{{Name: "get_resource", Schema: json.RawMessage(`{"type":"object"}`)}}

func TestClaudeThinkingBlocksAreReplayedVerbatim(t *testing.T) {
	const thinking = `{"type":"thinking","thinking":"","signature":"sig-abc+/="}`
	server, requests := claudeServer(t, `{"stop_reason":"tool_use","content":[`+thinking+`,{"type":"tool_use","id":"read-1","name":"get_resource","input":{"name":"app"}}]}`)
	p := claudeProvider(server.URL)
	first, err := p.Turn(context.Background(), Conversation{Tools: readTool, Messages: []Message{{Role: "user", Text: "investigate"}}})
	if err != nil || len(first.Calls) != 1 || len(first.ProviderItems) != 2 {
		t.Fatalf("thinking turn not parsed: %+v %v", first, err)
	}
	conversation := Conversation{Tools: readTool, Messages: []Message{{Role: "user", Text: "investigate"}, {Role: "assistant", ToolCalls: first.Calls, ProviderItems: first.ProviderItems}, {Role: "tool", ToolCallID: "read-1", Text: "observed"}}}
	if _, err := p.Turn(context.Background(), conversation); err != nil {
		t.Fatal(err)
	}
	assistant := (*requests)[1]["messages"].([]any)[1].(map[string]any)
	blocks := assistant["content"].([]any)
	if assistant["role"] != "assistant" || len(blocks) != 2 || blocks[0].(map[string]any)["signature"] != "sig-abc+/=" || blocks[1].(map[string]any)["type"] != "tool_use" {
		t.Fatalf("assistant turn not replayed verbatim: %v", assistant)
	}
}

func TestClaudeTextAnswerIsCorrectable(t *testing.T) {
	server, _ := claudeServer(t, `{"stop_reason":"end_turn","content":[{"type":"thinking","thinking":"","signature":"s"},{"type":"text","text":"The image tag is wrong."}]}`)
	_, err := claudeProvider(server.URL).Turn(context.Background(), Conversation{Tools: readTool, Messages: []Message{{Role: "user", Text: "investigate"}}})
	var proposal *ProposalError
	if !errors.As(err, &proposal) || !strings.Contains(proposal.Proposal, "image tag is wrong") || len(proposal.ProviderItems) != 2 {
		t.Fatalf("text answer should be a correctable proposal with its blocks: %v", err)
	}
}

func TestClaudeRefusalTruncationAndFallbackMarker(t *testing.T) {
	for response, want := range map[string]string{
		`{"stop_reason":"refusal","stop_details":{"category":"cyber"},"content":[]}`:                 "refusal category cyber",
		`{"stop_reason":"max_tokens","content":[{"type":"thinking","thinking":"","signature":"s"}]}`: "raise provider.maxOutputTokens",
	} {
		server, _ := claudeServer(t, response)
		if _, err := claudeProvider(server.URL).Turn(context.Background(), Conversation{Tools: readTool, Messages: []Message{{Role: "user", Text: "investigate"}}}); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q, got %v", want, err)
		}
	}
	calls, blocks, _, err := parseAnthropicTurn([]byte(`{"stop_reason":"tool_use","content":[{"type":"fallback","from":{"model":"claude-opus-5-5"},"to":{"model":"claude-opus-5"}},{"type":"tool_use","id":"read-1","name":"get_resource","input":{}}]}`))
	if err != nil || len(calls) != 1 || len(blocks) != 1 || strings.Contains(string(blocks[0]), "fallback") {
		t.Fatalf("fallback marker must not be replayed: %d calls %d blocks %v", len(calls), len(blocks), err)
	}
}

func TestClaudeEffortAndFallbacks(t *testing.T) {
	config := Config{Provider: "anthropic", BaseURL: anthropicAPI, Model: "claude-opus-5-5", ReasoningEffort: "high", MaxOutputTokens: 16000}
	payload := anthropicToolPayload(config, Conversation{Messages: []Message{{Role: "user", Text: "x"}}}, readTool, "instructions")
	if payload["fallbacks"] != "default" || payload["output_config"].(map[string]any)["effort"] != "high" {
		t.Fatalf("effort or fallbacks missing: %v", payload)
	}
	for _, other := range []Config{{BaseURL: "https://proxy.example/v1", Model: "claude-opus-5-5"}, {BaseURL: anthropicAPI, Model: "claude-haiku-4-5"}} {
		if anthropicFallbacks(other) {
			t.Fatalf("fallbacks enabled for %+v", other)
		}
	}
	if _, err := New(Config{Provider: "anthropic", ReasoningEffort: "none", APIKeyFile: "/dev/null"}); err == nil || !strings.Contains(err.Error(), "reasoning effort") {
		t.Fatalf("effort none accepted for Anthropic: %v", err)
	}
}
