package observation

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPrometheusOptionalAndBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"demo"},"value":[1,"0"]}]}}`))
	}))
	defer server.Close()
	tool, err := NewPrometheus(PrometheusConfig{BaseURL: server.URL, ScopeBoundary: "SingleNamespace", Namespaces: []string{"demo"}, AllowHTTPForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	result, err := tool.Call(context.Background(), api.Scope{Namespaces: []string{"demo"}}, ToolCall{ID: "metrics", Arguments: json.RawMessage(`{"query":"up"}`)})
	if err != nil || !json.Valid(result.Content) {
		t.Fatalf("query failed %v", err)
	}
	if _, err := tool.Call(context.Background(), api.Scope{Namespaces: []string{"other"}}, ToolCall{ID: "bad", Arguments: json.RawMessage(`{"query":"up{namespace=\"other\"}"}`)}); err == nil {
		t.Fatal("scope boundary ignored")
	}
}
func TestPrometheusRequiresOwnerAccessBoundary(t *testing.T) {
	if _, err := NewPrometheus(PrometheusConfig{BaseURL: "https://metrics.example"}); err == nil {
		t.Fatal("unisolated metrics source registered")
	}
}
