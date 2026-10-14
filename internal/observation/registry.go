package observation

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/policy"
	"sort"
	"sync"
	"time"
)

type Registry struct {
	Checkpoint func(context.Context) error
	// Repairs is what the owner opted into beyond the defaults; the model is told.
	Repairs   policy.Repairs
	reader    evidence.Reader
	mu        sync.Mutex
	tools     map[string]Tool
	remaining int
	bytes     int
}

func NewRegistry(reader evidence.Reader, p policy.Config, budget int) *Registry {
	r := &Registry{tools: map[string]Tool{}, remaining: budget, Repairs: p.Repairs, reader: reader}
	for _, name := range []string{"get_resource", "list_resources", "describe_api", "get_events", "get_pod_logs", "get_owner"} {
		r.Register(&kubernetesTool{name: name, reader: reader, policy: p})
	}
	r.Register(&eventsTool{reader: reader, policy: p})
	return r
}
func (r *Registry) Register(t Tool) { r.tools[t.Definition().Name] = t }

// StorageClasses names the cluster's StorageClasses for claim replacement, so
// a misspelled class is restored to the intended one rather than to whatever
// class another claim in the namespace uses. Nil when they cannot be read.
func (r *Registry) StorageClasses(ctx context.Context) []string {
	if r.reader == nil || !r.Repairs.Storage.ReplaceUnboundClaims {
		return nil
	}
	lister, ok := r.reader.(interface {
		StorageClassNames(context.Context) ([]string, error)
	})
	if !ok {
		return nil
	}
	names, err := lister.StorageClassNames(ctx)
	if err != nil {
		return nil
	}
	sort.Strings(names)
	return names
}
func (r *Registry) Definitions() []ToolDefinition {
	names := []string{}
	for n := range r.tools {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []ToolDefinition{}
	for _, n := range names {
		out = append(out, r.tools[n].Definition())
	}
	return out
}
func (r *Registry) Call(ctx context.Context, s api.Scope, c ToolCall) (ToolResult, error) {
	if err := s.Validate(); err != nil {
		return ToolResult{}, err
	}
	if c.ID == "" || len(c.ID) > 128 || len(c.Arguments) > 16384 {
		return ToolResult{}, fmt.Errorf("invalid tool call")
	}
	t, ok := r.tools[c.Name]
	if !ok {
		return ToolResult{}, fmt.Errorf("unknown read tool")
	}
	r.mu.Lock()
	if r.remaining <= 0 || r.bytes >= api.MaxEvidenceBytes {
		r.mu.Unlock()
		return ToolResult{}, fmt.Errorf("tool/evidence budget exhausted")
	}
	r.remaining--
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result, err := t.Call(ctx, s, c)
	if err != nil {
		return ToolResult{}, err
	}
	result.CallID = c.ID
	result.ObservedAt = time.Now().UTC()
	if len(result.Content) > api.MaxLogBytes {
		result.Content = json.RawMessage(`null`)
		result.Gap = "tool response exceeds size bound"
	}
	if len(result.Content) > 0 {
		result.Content = json.RawMessage(evidence.Redact(string(result.Content)))
		if !json.Valid(result.Content) {
			result.Content = json.RawMessage(`null`)
			result.Gap = "redaction removed structured evidence"
		}
	}
	result.Gap = evidence.Bound(evidence.Redact(result.Gap), 1024)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bytes+len(result.Content) > api.MaxEvidenceBytes {
		result.Content = json.RawMessage(`null`)
		result.Gap = "aggregate evidence budget exhausted"
	}
	r.bytes += len(result.Content)
	return result, nil
}
