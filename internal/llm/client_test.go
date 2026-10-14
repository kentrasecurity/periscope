package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const decisionJSON = `{"diagnosis":"wrong mode","risk":"low","actions":[{"id":"fix-1","type":"PatchResource","patch":[{"op":"replace","path":"/data/mode","value":"healthy"}]}],"verification":{"type":"FieldEquals","path":"/data/mode","expected":"healthy","timeoutSeconds":300,"stableWindowSeconds":120},"evidenceRefs":["evidence-1"]}`

func testConfig(t *testing.T, url, provider string) Config {
	t.Helper()
	file := filepath.Join(t.TempDir(), "key")
	if e := os.WriteFile(file, []byte("sk-proj-contract-canary123456789"), 0600); e != nil {
		t.Fatal(e)
	}
	return Config{Provider: provider, BaseURL: url, Model: "test-model", APIKeyFile: file, Timeout: time.Second, MaxResponseBytes: 1 << 20, MaxOutputTokens: 2048, AllowHTTPForTests: true}
}
func TestOpenAIRequestAndResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" || r.Header.Get("Authorization") != "Bearer sk-proj-contract-canary123456789" {
			t.Error("wrong OpenAI auth/path")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["model"] != "test-model" || body["messages"] == nil {
			t.Error("wrong body")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": decisionJSON}}}})
	}))
	defer srv.Close()
	c, e := New(testConfig(t, srv.URL, "openai"))
	if e != nil {
		t.Fatal(e)
	}
	d, e := c.Propose(context.Background(), Request{Objective: "fix"})
	if e != nil || len(d.Actions) != 1 {
		t.Fatalf("response %v", e)
	}
}
func TestAnthropicRequestAndResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/messages" || r.Header.Get("x-api-key") == "" || r.Header.Get("Authorization") != "" || r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Error("wrong Anthropic protocol")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["system"] == nil || body["max_tokens"] == nil {
			t.Error("missing native fields")
		}
		// Claude 5.5 models return (empty) thinking blocks before the answer.
		_ = json.NewEncoder(w).Encode(map[string]any{"stop_reason": "end_turn", "content": []any{map[string]any{"type": "thinking", "thinking": "", "signature": "s"}, map[string]any{"type": "text", "text": decisionJSON}}})
	}))
	defer srv.Close()
	c, e := New(testConfig(t, srv.URL, "anthropic"))
	if e != nil {
		t.Fatal(e)
	}
	d, e := c.Propose(context.Background(), Request{Objective: "fix"})
	if e != nil || d.Diagnosis != "wrong mode" {
		t.Fatalf("response %v", e)
	}
}
func TestNoCredentialRedirect(t *testing.T) {
	leaked := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer destination.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c, _ := New(testConfig(t, srv.URL, "openai"))
	_, e := c.Propose(context.Background(), Request{})
	if e == nil || leaked {
		t.Fatal("redirect followed")
	}
}
func TestRefusalTruncationAndOversize(t *testing.T) {
	for name, payload := range map[string]string{"truncated": `{"choices":[{"finish_reason":"length","message":{"content":"{}"}}]}`, "refused": `{"choices":[{"finish_reason":"stop","message":{"refusal":"no","content":"{}"}}]}`, "oversize": strings.Repeat("x", 4096)} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(payload)) }))
			defer srv.Close()
			cfg := testConfig(t, srv.URL, "openai")
			cfg.MaxResponseBytes = 1024
			c, _ := New(cfg)
			if _, e := c.Propose(context.Background(), Request{}); e == nil {
				t.Fatal("unsafe provider output accepted")
			}
		})
	}
}
func TestUnknownActionFieldsRejected(t *testing.T) {
	bad := strings.Replace(decisionJSON, `"id":"fix-1"`, `"id":"fix-1","shell":"kubectl create clusterrolebinding root"`, 1)
	if _, e := decodeDecision([]byte(bad), "key"); e == nil {
		t.Fatal("unknown action field accepted")
	}
	if _, e := decodeDecision([]byte(decisionJSON+` {}`), "key"); e == nil {
		t.Fatal("multiple JSON objects accepted")
	}
	misplaced := strings.Replace(decisionJSON, `"verification":{`, `"verification":{"target":{"kind":"Deployment"},`, 1)
	if _, e := decodeDecision([]byte(misplaced), "key"); e == nil || !strings.Contains(e.Error(), "verification {type") || !strings.Contains(e.Error(), "Each action names its own target") {
		t.Fatalf("misplaced field rejected without the decision shape: %v", e)
	}
}
func TestCredentialEchoRedacted(t *testing.T) {
	key := "sk-proj-contract-canary123456789"
	text := strings.Replace(decisionJSON, "wrong mode", key, 1)
	d, e := decodeDecision([]byte(text), key)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(d.Diagnosis, key) {
		t.Fatal("credential echoed")
	}
	text = strings.Replace(decisionJSON, "healthy", key, 1)
	if _, e := decodeDecision([]byte(text), key); e == nil {
		t.Fatal("credential became executable payload")
	}
}

func TestProposalPermissionModeSurvivesCredentialRedaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct{ Messages []struct{ Content string } }
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		var input map[string]any
		if err := json.Unmarshal([]byte(payload.Messages[len(payload.Messages)-1].Content), &input); err != nil {
			t.Fatal(err)
		}
		if input["permissionMode"] != "RBAC" {
			t.Error("safe permission mode hidden from planner")
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": decisionJSON}}}})
	}))
	defer server.Close()
	client, err := New(testConfig(t, server.URL, "openai"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Propose(context.Background(), Request{Authorization: "RBAC", Objective: "fixture"}); err != nil {
		t.Fatal(err)
	}
}

func TestAnthropicDefaultsToClaudeAndAnthropicAPI(t *testing.T) {
	cfg := testConfig(t, "", "anthropic")
	cfg.Model, cfg.BaseURL = "", ""
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := c.(*provider)
	if p.config.Model != "claude-opus-5-5" || p.config.BaseURL != "https://api.anthropic.com/v1" || p.config.API != "chat-completions" {
		t.Fatalf("unexpected Anthropic defaults: %+v", p.config)
	}
}

func TestSecretSourcesSurviveCredentialRedaction(t *testing.T) {
	create := `{"diagnosis":"missing Secret","risk":"low","actions":[{"id":"create-db","type":"CreateResource","target":{"apiVersion":"v1","kind":"Secret","namespace":"demo","name":"db"},"object":{"apiVersion":"v1","kind":"Secret","metadata":{"name":"db","namespace":"demo"},"type":"Opaque"},"secretSources":{"password":{"generate":32},"api-token":{"fromSecret":"template","fromKey":"token"}}}],"verification":{"type":"DeploymentRecovery","timeoutSeconds":180,"stableWindowSeconds":10},"evidenceRefs":[]}`
	d, err := decodeDecision([]byte(create), "key")
	if err != nil || d.Actions[0].SecretSources["password"].Generate != 32 {
		t.Fatalf("value-free Secret plan rejected: %v", err)
	}
	nested := strings.Replace(strings.Replace(create, `,"secretSources":{"password":{"generate":32},"api-token":{"fromSecret":"template","fromKey":"token"}}}]`, `}]`, 1), `"type":"Opaque"}`, `"type":"Opaque","secretSources":{"password":{"generate":32}}}`, 1)
	if d, err := decodeDecision([]byte(nested), "key"); err != nil || d.Actions[0].SecretSources["password"].Generate != 32 || d.Actions[0].Object["secretSources"] != nil {
		t.Fatalf("secretSources inside the object not moved to the action: %v %+v", err, d.Actions)
	}
	written := strings.Replace(create, `"type":"Opaque"}`, `"type":"Opaque","stringData":{"password":"hunter2-is-the-password"}}`, 1)
	if _, err := decodeDecision([]byte(written), "key"); err == nil || !strings.Contains(err.Error(), "credential-like value") {
		t.Fatalf("model-written credential accepted: %v", err)
	}
}
