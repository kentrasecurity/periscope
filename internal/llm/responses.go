package llm

import (
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/observation"
)

// Responses uses stateless replay. Encrypted reasoning is kept only in the
// investigation's in-memory conversation, never written to evidence or CRDs.
func responsesPayload(config Config, c Conversation, definitions []observation.ToolDefinition, instructions string) (map[string]any, string) {
	tools := []any{}
	for _, d := range definitions {
		tools = append(tools, map[string]any{"type": "function", "name": d.Name, "description": d.Description, "parameters": d.Schema, "strict": false})
	}
	input := []any{}
	for _, m := range c.Messages {
		for _, item := range m.ProviderItems {
			input = append(input, item)
		}
		if m.Role == "tool" {
			input = append(input, map[string]any{"type": "function_call_output", "call_id": m.ToolCallID, "output": m.Text})
			continue
		}
		if m.Text != "" {
			input = append(input, map[string]any{"role": m.Role, "content": m.Text})
		}
		for _, call := range m.ToolCalls {
			input = append(input, map[string]any{"type": "function_call", "call_id": call.ID, "name": call.Name, "arguments": string(call.Arguments)})
		}
	}
	return map[string]any{"model": config.Model, "instructions": instructions, "input": input, "tools": tools, "tool_choice": "required", "store": false, "reasoning": map[string]any{"effort": config.ReasoningEffort}, "max_output_tokens": config.MaxOutputTokens}, "/responses"
}

func parseResponsesCalls(raw []byte) ([]observation.ToolCall, []json.RawMessage, error) {
	var response struct {
		Status string            `json:"status"`
		Output []json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || response.Status != "completed" {
		return nil, nil, fmt.Errorf("invalid/incomplete OpenAI Responses turn")
	}
	calls := []observation.ToolCall{}
	reasoning := []json.RawMessage{}
	for _, rawItem := range response.Output {
		var item struct {
			Type, ID, Name, Arguments, Status string
			CallID                            string `json:"call_id"`
			Encrypted                         string `json:"encrypted_content"`
		}
		if json.Unmarshal(rawItem, &item) != nil {
			return nil, nil, fmt.Errorf("invalid Responses output item")
		}
		switch item.Type {
		case "function_call":
			if item.Status != "completed" {
				return nil, nil, fmt.Errorf("incomplete Responses tool call")
			}
			calls = append(calls, observation.ToolCall{ID: item.CallID, Name: item.Name, Arguments: json.RawMessage(item.Arguments)})
		case "reasoning":
			if item.ID == "" || item.Encrypted == "" {
				return nil, nil, fmt.Errorf("missing stateless reasoning continuation")
			}
			// Replay only protocol fields and opaque encrypted content; summaries and
			// plaintext model output are not added to executable context.
			safe, _ := json.Marshal(map[string]any{"type": "reasoning", "id": item.ID, "summary": []any{}, "encrypted_content": item.Encrypted})
			reasoning = append(reasoning, safe)
		default:
			return nil, nil, fmt.Errorf("unexpected Responses output instead of tool call")
		}
	}
	return calls, reasoning, nil
}
