package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativeProbeProtocolsAreBounded(t *testing.T) {
	for _, request := range []Request{{Type: "exec", Host: "example.org", TimeoutSeconds: 1}, {Type: "HTTP", URL: "http://example.org", TimeoutSeconds: 6}, {Type: "TCP", Host: "example.org", Port: 0, TimeoutSeconds: 1}} {
		if _, err := Run(context.Background(), request, "agent-context"); err == nil {
			t.Fatal("invalid probe accepted")
		}
	}
}
func TestNativeProbeHTTPDoesNotFollowRedirect(t *testing.T) {
	reached := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true; w.WriteHeader(200) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer redirect.Close()
	result, err := Run(context.Background(), Request{Type: "HTTP", URL: redirect.URL, TimeoutSeconds: 1}, "agent-context")
	if err != nil || result.Success || reached {
		t.Fatal("redirect reached undeclared destination")
	}
}
