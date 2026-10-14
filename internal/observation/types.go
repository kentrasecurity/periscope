package observation

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"time"
)

type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}
type ToolResult struct {
	CallID     string          `json:"callID"`
	Source     string          `json:"source"`
	ObservedAt time.Time       `json:"observedAt"`
	Content    json.RawMessage `json:"content,omitempty"`
	Gap        string          `json:"gap,omitempty"`
}
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
}
type Tool interface {
	Definition() ToolDefinition
	Call(context.Context, api.Scope, ToolCall) (ToolResult, error)
}
