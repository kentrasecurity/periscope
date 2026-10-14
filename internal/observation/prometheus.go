package observation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type PrometheusConfig struct {
	BaseURL           string   `json:"baseURL"`
	TokenFile         string   `json:"tokenFile,omitempty"`
	ScopeBoundary     string   `json:"scopeBoundary"`
	Namespaces        []string `json:"namespaces"`
	TimeoutSeconds    int      `json:"timeoutSeconds,omitempty"`
	MaxSeries         int      `json:"maxSeries,omitempty"`
	MaxPoints         int      `json:"maxPoints,omitempty"`
	AllowHTTP         bool     `json:"allowHTTP,omitempty"`
	AllowHTTPForTests bool     `json:"-"`
}
type prometheusTool struct {
	config PrometheusConfig
	token  string
	http   *http.Client
}

func NewPrometheus(c PrometheusConfig) (Tool, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "https" && !(u.Scheme == "http" && (c.AllowHTTP || c.AllowHTTPForTests)) {
		return nil, fmt.Errorf("invalid configured Prometheus endpoint")
	}
	if c.ScopeBoundary != "SingleNamespace" && c.ScopeBoundary != "OwnerTenant" {
		return nil, fmt.Errorf("owner Prometheus access boundary required")
	}
	if err := (api.Scope{Namespaces: c.Namespaces}).Validate(); err != nil {
		return nil, err
	}
	if c.ScopeBoundary == "SingleNamespace" && len(c.Namespaces) != 1 {
		return nil, fmt.Errorf("single-namespace source requires one namespace")
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 5
	}
	if c.MaxSeries == 0 {
		c.MaxSeries = 100
	}
	if c.MaxPoints == 0 {
		c.MaxPoints = 1000
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 10 || c.MaxSeries < 1 || c.MaxSeries > 100 || c.MaxPoints < 1 || c.MaxPoints > 1000 {
		return nil, fmt.Errorf("invalid Prometheus bounds")
	}
	token := ""
	if c.TokenFile != "" {
		b, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("Prometheus credential unavailable")
		}
		token = strings.TrimSpace(string(b))
		if token == "" || len(token) > 8192 {
			return nil, fmt.Errorf("invalid Prometheus credential")
		}
	}
	return &prometheusTool{config: c, token: token, http: &http.Client{Timeout: time.Duration(c.TimeoutSeconds) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("metrics redirects forbidden") }}}, nil
}
func (p *prometheusTool) Definition() ToolDefinition {
	return ToolDefinition{Name: "query_prometheus", Description: "Read owner-isolated Prometheus observations. Missing metrics is an evidence gap, not success.", Schema: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["query"],"properties":{"query":{"type":"string","maxLength":8192},"start":{"type":"integer"},"end":{"type":"integer"},"stepSeconds":{"type":"integer"}}}`)}
}
func (p *prometheusTool) Call(ctx context.Context, s api.Scope, c ToolCall) (ToolResult, error) {
	source := append([]string(nil), p.config.Namespaces...)
	task := append([]string(nil), s.Namespaces...)
	sort.Strings(source)
	sort.Strings(task)
	if strings.Join(source, "\x00") != strings.Join(task, "\x00") || len(s.Resources) > 0 {
		return ToolResult{}, fmt.Errorf("metrics source boundary must exactly cover task observation scope")
	}
	var args struct {
		Query       string `json:"query"`
		Start       int64  `json:"start"`
		End         int64  `json:"end"`
		StepSeconds int    `json:"stepSeconds"`
	}
	d := json.NewDecoder(bytes.NewReader(c.Arguments))
	d.DisallowUnknownFields()
	if err := d.Decode(&args); err != nil {
		return ToolResult{}, err
	}
	if args.Query == "" || len(args.Query) > 8192 || d.Decode(new(any)) != io.EOF {
		return ToolResult{}, fmt.Errorf("invalid metrics query")
	}
	values := url.Values{"query": []string{args.Query}}
	path := "/api/v1/query"
	if args.Start != 0 || args.End != 0 || args.StepSeconds != 0 {
		if args.Start <= 0 || args.End <= args.Start || args.End-args.Start > 3600 || args.StepSeconds < 1 || (args.End-args.Start)/int64(args.StepSeconds)+1 > int64(p.config.MaxPoints) {
			return ToolResult{}, fmt.Errorf("invalid metrics time range")
		}
		path = "/api/v1/query_range"
		values.Set("start", strconv.FormatInt(args.Start, 10))
		values.Set("end", strconv.FormatInt(args.End, 10))
		values.Set("step", strconv.Itoa(args.StepSeconds))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(p.config.BaseURL, "/")+path+"?"+values.Encode(), nil)
	if err != nil {
		return ToolResult{}, err
	}
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	out := ToolResult{CallID: c.ID, Source: "prometheus:" + p.config.BaseURL, ObservedAt: time.Now().UTC()}
	response, err := p.http.Do(req)
	if err != nil {
		out.Gap = "metrics source unavailable"
		return out, nil
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		out.Gap = fmt.Sprintf("metrics source returned HTTP %d", response.StatusCode)
		return out, nil
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(b) > 65536 {
		out.Gap = "metrics response exceeds size bound or unavailable"
		return out, nil
	}
	var data struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string          `json:"resultType"`
			Result     json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &data) != nil || data.Status != "success" {
		out.Gap = "metrics query failed or returned malformed data"
		return out, nil
	}
	if data.Data.ResultType != "vector" && data.Data.ResultType != "matrix" {
		out.Gap = "metrics result must retain series provenance"
		return out, nil
	}
	var series []struct {
		Values []json.RawMessage `json:"values"`
	}
	if json.Unmarshal(data.Data.Result, &series) != nil || len(series) > p.config.MaxSeries {
		out.Gap = "metrics series limit exceeded"
		return out, nil
	}
	points := 0
	for _, item := range series {
		if data.Data.ResultType == "vector" {
			points++
		} else {
			points += len(item.Values)
		}
	}
	if points > p.config.MaxPoints {
		out.Gap = "metrics point limit exceeded"
		return out, nil
	}
	if p.token != "" {
		b = []byte(strings.ReplaceAll(string(b), p.token, "[REDACTED]"))
	}
	b = []byte(evidence.Redact(string(b)))
	if !json.Valid(b) {
		out.Gap = "metrics evidence invalid after redaction"
		return out, nil
	}
	out.Content = b
	return out, nil
}
