package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/observation"
	"strings"
)

const anthropicAPI = "https://api.anthropic.com/v1"

// fallbackBeta enables server-side refusal fallbacks: when a safety classifier
// declines a request (benign Kubernetes security work can trigger one), the
// API re-runs it on Anthropic's recommended model for that refusal category.
const fallbackBeta = "server-side-fallback-2026-07-01"

// anthropicFallbacks reports whether requests opt into server-side refusal
// fallbacks: only on the Claude API itself and for models that support them.
func anthropicFallbacks(c Config) bool {
	if strings.TrimRight(c.BaseURL, "/") != anthropicAPI {
		return false
	}
	switch c.Model {
	case "claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5":
		return true
	}
	return false
}

// anthropicRequest adds the options shared by every Messages API call.
// Thinking is left at the model default (always-on adaptive thinking on
// Claude 5.5 models); effort is the control for depth, latency and cost.
func anthropicRequest(c Config, payload map[string]any) map[string]any {
	if c.ReasoningEffort != "" {
		payload["output_config"] = map[string]any{"effort": c.ReasoningEffort}
	}
	if anthropicFallbacks(c) {
		payload["fallbacks"] = "default"
	}
	return payload
}

func (p *provider) anthropic(ctx context.Context, text string) (Decision, error) {
	payload := anthropicRequest(p.config, map[string]any{"model": p.config.Model, "system": systemInstructions, "max_tokens": p.config.MaxOutputTokens, "messages": []any{map[string]string{"role": "user", "content": text}}})
	b, e := p.post(ctx, "/messages", payload)
	if e != nil {
		return Decision{}, e
	}
	_, _, answer, e := parseAnthropicTurn(b)
	if e != nil {
		return Decision{}, e
	}
	return decodeDecision([]byte(answer), p.key)
}

func anthropicToolPayload(config Config, c Conversation, definitions []observation.ToolDefinition, instructions string) map[string]any {
	tools := []any{}
	for _, d := range definitions {
		tools = append(tools, map[string]any{"name": d.Name, "description": d.Description, "input_schema": d.Schema})
	}
	// Forced tool choice ("any") is rejected by Claude 5.5 models; "auto" plus
	// the instruction to answer only with tool calls, and a correction turn
	// when the model answers in text, keep the tool-only protocol.
	return anthropicRequest(config, map[string]any{"model": config.Model, "system": []any{map[string]any{"type": "text", "text": instructions, "cache_control": ephemeral()}}, "messages": anthropicMessages(c.Messages), "tools": tools, "tool_choice": map[string]any{"type": "auto"}, "max_tokens": config.MaxOutputTokens})
}

func ephemeral() map[string]any { return map[string]any{"type": "ephemeral"} }

// anthropicMessages converts the conversation to Messages API turns. Assistant
// turns returned by the API are replayed verbatim from their content blocks:
// thinking blocks must go back unchanged in tool loops, and the history stays
// append-only so their binding to the conversation holds. All tool results
// answering one assistant turn must arrive in a single user turn, so
// consecutive same-role messages are merged. Every investigation turn resends
// the growing evidence, so the system prompt (with the tools before it) and the
// latest turn carry cache breakpoints; later turns read the prefix from the
// prompt cache.
func anthropicMessages(conversation []Message) []any {
	type turn struct {
		role    string
		content []any
	}
	turns := []turn{}
	for _, m := range conversation {
		role := m.Role
		content := []any{}
		switch {
		case role == "tool":
			role = "user"
			content = append(content, map[string]any{"type": "tool_result", "tool_use_id": m.ToolCallID, "content": m.Text})
		case role == "assistant" && len(m.ProviderItems) > 0:
			for _, block := range m.ProviderItems {
				content = append(content, block)
			}
		default:
			if m.Text != "" {
				content = append(content, map[string]any{"type": "text", "text": m.Text})
			}
			for _, call := range m.ToolCalls {
				content = append(content, map[string]any{"type": "tool_use", "id": call.ID, "name": call.Name, "input": call.Arguments})
			}
		}
		if len(content) == 0 {
			continue
		}
		if n := len(turns); n > 0 && turns[n-1].role == role {
			turns[n-1].content = append(turns[n-1].content, content...)
			continue
		}
		turns = append(turns, turn{role: role, content: content})
	}
	// The conversation ends with a user turn built here, never a replayed block.
	if n := len(turns); n > 0 {
		last := turns[n-1].content
		if block, ok := last[len(last)-1].(map[string]any); ok {
			block["cache_control"] = ephemeral()
		}
	}
	messages := make([]any, 0, len(turns))
	for _, t := range turns {
		messages = append(messages, map[string]any{"role": t.role, "content": t.content})
	}
	return messages
}

// parseAnthropicTurn returns a response's tool calls, its content blocks for
// verbatim replay and its text. Blocks before a fallback marker belong to a
// declined attempt and are not replayed. A refusal or truncation is an error;
// a plain-text answer (stop_reason end_turn) returns no calls.
func parseAnthropicTurn(raw []byte) ([]observation.ToolCall, []json.RawMessage, string, error) {
	var response struct {
		StopReason  string `json:"stop_reason"`
		StopDetails *struct {
			Category string `json:"category"`
		} `json:"stop_details"`
		Content []json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, nil, "", fmt.Errorf("invalid Anthropic response")
	}
	switch response.StopReason {
	case "tool_use", "end_turn":
	case "refusal":
		category := "unspecified"
		if response.StopDetails != nil && response.StopDetails.Category != "" {
			category = evidence.Bound(response.StopDetails.Category, 64)
		}
		return nil, nil, "", fmt.Errorf("Anthropic declined the request (refusal category %s)", category)
	case "max_tokens":
		return nil, nil, "", fmt.Errorf("Anthropic response reached max_tokens; raise provider.maxOutputTokens")
	default:
		return nil, nil, "", fmt.Errorf("incomplete Anthropic turn: stop_reason %q", evidence.Bound(response.StopReason, 64))
	}
	calls := []observation.ToolCall{}
	blocks := []json.RawMessage{}
	texts := []string{}
	for _, block := range response.Content {
		var b struct {
			Type, ID, Name, Text string
			Input                json.RawMessage `json:"input"`
		}
		if json.Unmarshal(block, &b) != nil {
			return nil, nil, "", fmt.Errorf("invalid Anthropic content block")
		}
		switch b.Type {
		case "fallback":
			calls, blocks, texts = calls[:0], blocks[:0], texts[:0]
			continue
		case "tool_use":
			calls = append(calls, observation.ToolCall{ID: b.ID, Name: b.Name, Arguments: b.Input})
		case "text":
			texts = append(texts, b.Text)
		case "thinking", "redacted_thinking":
		default:
			return nil, nil, "", fmt.Errorf("unexpected Anthropic content type %q", evidence.Bound(b.Type, 64))
		}
		blocks = append(blocks, block)
	}
	if response.StopReason == "tool_use" && len(calls) == 0 {
		return nil, nil, "", fmt.Errorf("Anthropic tool turn without tool calls")
	}
	return calls, blocks, strings.Join(texts, ""), nil
}
