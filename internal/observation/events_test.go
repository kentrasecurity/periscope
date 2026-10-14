package observation

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"strings"
	"testing"
	"time"
)

func event(message, eventType, involvedName, reason string, minute int) map[string]any {
	return map[string]any{"type": eventType, "reason": reason, "message": message, "lastTimestamp": time.Date(2026, 1, 1, 0, minute, 0, 0, time.UTC).Format(time.RFC3339), "involvedObject": map[string]any{"apiVersion": "v1", "kind": "Pod", "name": involvedName}}
}

func TestListEventsIsScopedFilteredAndNewestFirst(t *testing.T) {
	b := testkit.NewMemory()
	b.PutResource(testkit.Resource("v1", "Event", "demo", "old", "1", event("old-warning", "Warning", "web", "BackOff", 1)))
	b.PutResource(testkit.Resource("v1", "Event", "demo", "new", "2", event("new-warning", "Warning", "web", "BackOff", 5)))
	b.PutResource(testkit.Resource("v1", "Event", "demo", "normal", "3", event("normal-event", "Normal", "web", "Pulled", 6)))
	b.PutResource(testkit.Resource("v1", "Event", "demo", "private", "4", event("private-warning", "Warning", "secret-app", "BackOff", 7)))
	r := NewRegistry(b, policy.Config{Authorization: "RBAC", Namespaces: []string{"demo"}}, 10)
	scope := api.Scope{Namespaces: []string{"demo"}, Resources: []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod", Name: "web"}}}
	result, err := r.Call(context.Background(), scope, ToolCall{ID: "ev", Name: "list_events", Arguments: json.RawMessage(`{"namespace":"demo","type":"Warning"}`)})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	if err := json.Unmarshal(result.Content, &lines); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(lines, "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "new-warning") || !strings.Contains(lines[1], "old-warning") {
		t.Fatalf("expected two Warnings newest first, got %q", joined)
	}
	if strings.Contains(joined, "private-warning") || strings.Contains(joined, "normal-event") {
		t.Fatalf("out-of-scope or filtered Event returned: %q", joined)
	}
	if _, err := r.Call(context.Background(), scope, ToolCall{ID: "other", Name: "list_events", Arguments: json.RawMessage(`{"namespace":"kube-system"}`)}); err == nil {
		t.Fatal("namespace outside scope accepted")
	}
	for _, args := range []string{
		`{"namespace":"demo","reason":"BackOff,involvedObject.name=secret-app"}`,
		`{"namespace":"demo","involvedName":"web!=x"}`,
		`{"namespace":"demo","limit":101}`,
		`{"namespace":"demo","type":"Error"}`,
	} {
		if _, err := r.Call(context.Background(), scope, ToolCall{ID: "bad", Name: "list_events", Arguments: json.RawMessage(args)}); err == nil {
			t.Fatalf("invalid list_events arguments accepted: %s", args)
		}
	}
	result, err = r.Call(context.Background(), scope, ToolCall{ID: "reason", Name: "list_events", Arguments: json.RawMessage(`{"namespace":"demo","reason":"Pulled","involvedName":"web"}`)})
	if err != nil || !strings.Contains(string(result.Content), "normal-event") || strings.Contains(string(result.Content), "warning") {
		t.Fatalf("reason/involved filters not applied: %s %v", result.Content, err)
	}
}
