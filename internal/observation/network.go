package observation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/probe"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type ProbeRequest = probe.Request
type ProbeResult = probe.Result
type ProbeClient interface {
	Check(context.Context, api.TargetRef, ProbeRequest) (ProbeResult, error)
}
type ProbeEndpoint struct {
	Target       api.TargetRef  `json:"target"`
	URL          string         `json:"url"`
	TokenFile    string         `json:"tokenFile"`
	Destinations []ProbeRequest `json:"destinations"`
}
type NetworkConfig struct {
	Endpoints []ProbeEndpoint `json:"endpoints"`
	AllowHTTP bool            `json:"allowHTTP,omitempty"`
}
type Network struct {
	config NetworkConfig
	Reader evidence.Reader
}

func NewNetwork(config NetworkConfig) (*Network, error) {
	if len(config.Endpoints) > 32 {
		return nil, fmt.Errorf("too many probe endpoints")
	}
	for _, endpoint := range config.Endpoints {
		u, err := url.Parse(endpoint.URL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "https" && !(u.Scheme == "http" && config.AllowHTTP)) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || endpoint.TokenFile == "" || endpoint.Target.APIVersion != "v1" || endpoint.Target.Kind != "Pod" || endpoint.Target.Namespace == "" || endpoint.Target.Name == "" || endpoint.Target.UID == "" || len(endpoint.Destinations) < 1 || len(endpoint.Destinations) > 32 {
			return nil, fmt.Errorf("invalid owner probe endpoint or pinned Pod UID")
		}
		for _, r := range endpoint.Destinations {
			if err := r.Validate(); err != nil {
				return nil, err
			}
		}
	}
	return &Network{config: config}, nil
}
func (n *Network) Check(ctx context.Context, target api.TargetRef, request ProbeRequest) (ProbeResult, error) {
	if err := request.Validate(); err != nil {
		return ProbeResult{}, err
	}
	for _, endpoint := range n.config.Endpoints {
		if endpoint.Target != target {
			continue
		}
		allowed := false
		for _, r := range endpoint.Destinations {
			if probe.SameDestination(r, request) {
				allowed = true
			}
		}
		if !allowed {
			return ProbeResult{}, fmt.Errorf("probe destination not owner-declared")
		}
		token, err := os.ReadFile(endpoint.TokenFile)
		if err != nil || len(token) < 16 || len(token) > 8192 {
			return ProbeResult{}, fmt.Errorf("probe credential unavailable")
		}
		payload, _ := json.Marshal(request)
		ctx, cancel := context.WithTimeout(ctx, time.Duration(request.TimeoutSeconds+1)*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint.URL, "/")+"/check", bytes.NewReader(payload))
		if err != nil {
			return ProbeResult{}, fmt.Errorf("probe request invalid")
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		req.Header.Set("Content-Type", "application/json")
		client := http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		defer client.CloseIdleConnections()
		response, err := client.Do(req)
		if err != nil {
			return ProbeResult{}, fmt.Errorf("owner probe endpoint unreachable")
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return ProbeResult{}, fmt.Errorf("owner probe rejected observation")
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, 8193))
		if err != nil || len(raw) > 8192 {
			return ProbeResult{}, fmt.Errorf("probe response exceeds bounds")
		}
		var result ProbeResult
		if json.Unmarshal(raw, &result) != nil || result.Vantage != "pod:"+target.UID || result.ObservedAt.IsZero() || time.Since(result.ObservedAt) > 10*time.Second || time.Until(result.ObservedAt) > 5*time.Second {
			return ProbeResult{}, fmt.Errorf("monitored Pod vantage unavailable or stale")
		}
		result.Detail = boundedProbeDetail(result.Detail)
		return result, nil
	}
	return ProbeResult{}, fmt.Errorf("owner-installed probe missing for monitored Pod UID")
}
func boundedProbeDetail(s string) string {
	if len(s) > 1024 {
		return s[:1024]
	}
	return s
}
func (n *Network) Definition() ToolDefinition {
	return ToolDefinition{Name: "probe_network", Description: "Owner-installed monitored-Pod native observation. Use the observed Pod UID. HTTP needs request.url; DNS needs request.host; TCP needs request.host and request.port. Use timeoutSeconds 1..5 and only the explicitly owner-declared destination.", Schema: json.RawMessage(`{"type":"object","properties":{"target":{"type":"object","properties":{"apiVersion":{"type":"string","enum":["v1"]},"kind":{"type":"string","enum":["Pod"]},"namespace":{"type":"string"},"name":{"type":"string"},"uid":{"type":"string"}},"required":["apiVersion","kind","namespace","name","uid"],"additionalProperties":false},"request":{"type":"object","properties":{"type":{"type":"string","enum":["DNS","TCP","HTTP"]},"host":{"type":"string"},"url":{"type":"string"},"port":{"type":"integer","minimum":1,"maximum":65535},"timeoutSeconds":{"type":"integer","minimum":1,"maximum":5}},"required":["type","timeoutSeconds"],"additionalProperties":false}},"required":["target","request"],"additionalProperties":false}`)}
}
func (n *Network) Call(ctx context.Context, scope api.Scope, call ToolCall) (ToolResult, error) {
	var args struct {
		Target  api.TargetRef `json:"target"`
		Request ProbeRequest  `json:"request"`
	}
	decoder := json.NewDecoder(bytes.NewReader(call.Arguments))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&args); err != nil {
		return ToolResult{}, fmt.Errorf("invalid network arguments")
	}
	if !scope.Contains(args.Target) {
		return ToolResult{}, fmt.Errorf("probe target outside scope")
	}
	if n.Reader != nil {
		target, err := n.Reader.Get(ctx, args.Target)
		if err != nil || !scope.Matches(args.Target, target) || string(target.GetUID()) != args.Target.UID {
			return ToolResult{}, fmt.Errorf("network target selector or UID changed")
		}
	} else if len(scope.Resources) > 0 {
		return ToolResult{}, fmt.Errorf("network scope selector observation unavailable")
	}
	result, err := n.Check(ctx, args.Target, args.Request)
	if err != nil {
		return ToolResult{CallID: call.ID, Source: "owner-probe", ObservedAt: time.Now().UTC(), Gap: err.Error(), Content: json.RawMessage("null")}, nil
	}
	payload, _ := json.Marshal(result)
	return ToolResult{CallID: call.ID, Source: result.Vantage, ObservedAt: result.ObservedAt, Content: payload}, nil
}
