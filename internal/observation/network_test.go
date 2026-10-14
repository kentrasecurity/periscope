package observation

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNetworkProbeVantageCannotBeSubstituted(t *testing.T) {
	network, _ := NewNetwork(NetworkConfig{})
	_, err := network.Check(context.Background(), api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "app", UID: "uid"}, ProbeRequest{Type: "DNS", Host: "localhost", TimeoutSeconds: 1})
	if err == nil {
		t.Fatal("missing Pod probe accepted agent vantage")
	}
}
func TestNetworkEndpointRejectsForgedVantage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ProbeResult{Success: true, Vantage: "agent-context", ObservedAt: time.Now()})
	}))
	defer server.Close()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("test-probe-token-123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	target := api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: "demo", Name: "app", UID: "uid"}
	request := ProbeRequest{Type: "HTTP", URL: "http://service/", TimeoutSeconds: 1}
	network, err := NewNetwork(NetworkConfig{AllowHTTP: true, Endpoints: []ProbeEndpoint{{Target: target, URL: server.URL, TokenFile: token, Destinations: []ProbeRequest{request}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := network.Check(context.Background(), target, request); err == nil {
		t.Fatal("forged vantage accepted")
	}
}

func TestNetworkDefinitionDescribesNativeTargetAndRequest(t *testing.T) {
	network, err := NewNetwork(NetworkConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	json.Unmarshal(network.Definition().Schema, &schema)
	properties := schema["properties"].(map[string]any)
	for field, expected := range map[string][]string{"target": {"apiVersion", "kind", "namespace", "name", "uid"}, "request": {"type", "host", "url", "port", "timeoutSeconds"}} {
		nested := properties[field].(map[string]any)
		fields, ok := nested["properties"].(map[string]any)
		if !ok {
			t.Fatalf("native %s schema leaves model to guess argument fields", field)
		}
		for _, name := range expected {
			if fields[name] == nil {
				t.Errorf("missing %s.%s", field, name)
			}
		}
	}
}
