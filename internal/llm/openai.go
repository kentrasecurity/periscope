package llm

import (
	"context"
	"encoding/json"
	"fmt"
)

func (p *provider) openai(ctx context.Context, text string) (Decision, error) {
	payload := map[string]any{"model": p.config.Model, "messages": []any{map[string]string{"role": "system", "content": systemInstructions}, map[string]string{"role": "user", "content": text}}, "max_completion_tokens": p.config.MaxOutputTokens, "response_format": map[string]string{"type": "json_object"}}
	b, e := p.post(ctx, "/chat/completions", payload)
	if e != nil {
		return Decision{}, e
	}
	var response struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content string  `json:"content"`
				Refusal *string `json:"refusal"`
			} `json:"message"`
		} `json:"choices"`
	}
	if e = json.Unmarshal(b, &response); e != nil || len(response.Choices) != 1 {
		return Decision{}, fmt.Errorf("invalid OpenAI response")
	}
	choice := response.Choices[0]
	if choice.FinishReason != "stop" || choice.Message.Refusal != nil {
		return Decision{}, fmt.Errorf("OpenAI decision refused or incomplete")
	}
	return decodeDecision([]byte(choice.Message.Content), p.key)
}
