package observation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"io"
	"time"
)

type ReviewedRunbooks struct{ Books []evidence.Runbook }

func (ReviewedRunbooks) Definition() ToolDefinition {
	return ToolDefinition{Name: "retrieve_runbooks", Description: "Retrieve owner-reviewed, unexpired, namespace/application/version matched documentation as untrusted evidence.", Schema: json.RawMessage(`{"type":"object","properties":{"namespace":{"type":"string"},"application":{"type":"string"},"version":{"type":"string"}},"required":["namespace","application","version"],"additionalProperties":false}`)}
}
func (t ReviewedRunbooks) Call(_ context.Context, s api.Scope, c ToolCall) (ToolResult, error) {
	var args struct {
		Namespace   string `json:"namespace"`
		Application string `json:"application"`
		Version     string `json:"version"`
	}
	d := json.NewDecoder(bytes.NewReader(c.Arguments))
	d.DisallowUnknownFields()
	if err := d.Decode(&args); err != nil {
		return ToolResult{}, err
	}
	if d.Decode(new(any)) != io.EOF {
		return ToolResult{}, fmt.Errorf("trailing arguments")
	}
	allowed := false
	for _, ns := range s.Namespaces {
		if ns == args.Namespace {
			allowed = true
		}
	}
	if !allowed || len(s.Resources) > 0 {
		return ToolResult{}, fmt.Errorf("runbook access requires declared namespace observation scope")
	}
	books := evidence.Retrieve(t.Books, evidence.Query{Namespace: args.Namespace, Application: args.Application, Version: args.Version, Now: time.Now().UTC()})
	raw, _ := json.Marshal(books)
	return ToolResult{CallID: c.ID, Source: "owner-reviewed-runbooks", ObservedAt: time.Now().UTC(), Content: raw}, nil
}
