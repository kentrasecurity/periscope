// Package probe implements fixed native observations, never commands or shell execution.
package probe

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Request struct {
	Type           string `json:"type"`
	Host           string `json:"host,omitempty"`
	URL            string `json:"url,omitempty"`
	Port           int    `json:"port,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}
type Result struct {
	Success    bool      `json:"success"`
	ObservedAt time.Time `json:"observedAt"`
	Vantage    string    `json:"vantage"`
	Detail     string    `json:"detail"`
}

func (r Request) Validate() error {
	if r.TimeoutSeconds < 1 || r.TimeoutSeconds > 5 {
		return fmt.Errorf("timeout must be 1..5 seconds")
	}
	if len(r.Host) > 253 || len(r.URL) > 2048 {
		return fmt.Errorf("destination exceeds bounds")
	}
	switch r.Type {
	case "DNS":
		if r.Host == "" || r.URL != "" || r.Port != 0 {
			return fmt.Errorf("DNS needs a host only")
		}
	case "TCP":
		if r.Host == "" || r.URL != "" || r.Port < 1 || r.Port > 65535 {
			return fmt.Errorf("TCP needs host and port")
		}
	case "HTTP":
		u, err := url.Parse(r.URL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || r.Host != "" || r.Port != 0 {
			return fmt.Errorf("HTTP needs an explicit http(s) URL without credentials")
		}
	default:
		return fmt.Errorf("unsupported native probe")
	}
	return nil
}
func SameDestination(a, b Request) bool {
	return a.Type == b.Type && a.Host == b.Host && a.URL == b.URL && a.Port == b.Port
}
func Run(ctx context.Context, r Request, vantage string) (Result, error) {
	if err := r.Validate(); err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.TimeoutSeconds)*time.Second)
	defer cancel()
	result := Result{ObservedAt: time.Now().UTC(), Vantage: vantage}
	var err error
	switch r.Type {
	case "DNS":
		var addresses []string
		addresses, err = net.DefaultResolver.LookupHost(ctx, r.Host)
		result.Success = err == nil && len(addresses) > 0
		result.Detail = "DNS lookup completed"
	case "TCP":
		var connection net.Conn
		connection, err = (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(r.Host, strconv.Itoa(r.Port)))
		result.Success = err == nil
		if connection != nil {
			_ = connection.Close()
		}
		result.Detail = "TCP connection completed"
	case "HTTP":
		var request *http.Request
		request, err = http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
		if err == nil {
			client := http.Client{Timeout: time.Duration(r.TimeoutSeconds) * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			var response *http.Response
			response, err = client.Do(request)
			if response != nil {
				result.Success = response.StatusCode >= 200 && response.StatusCode < 300
				result.Detail = fmt.Sprintf("HTTP status %d", response.StatusCode)
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
				_ = response.Body.Close()
				client.CloseIdleConnections()
			}
		}
	}
	if err != nil {
		result.Detail = "Native observation failed"
	}
	return result, nil
}

type Server struct {
	Token, Vantage string
	Destinations   []Request
}

func (s Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if s.Token == "" || len(token) != len(s.Token) || subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/check" {
		http.Error(w, "unsupported request", 405)
		return
	}
	var request Request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid probe", 400)
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		http.Error(w, "invalid probe", 400)
		return
	}
	allowed := false
	for _, destination := range s.Destinations {
		if SameDestination(request, destination) {
			allowed = true
		}
	}
	if !allowed {
		http.Error(w, "destination not declared by owner", 403)
		return
	}
	result, err := Run(r.Context(), request, s.Vantage)
	if err != nil {
		http.Error(w, "invalid probe", 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
