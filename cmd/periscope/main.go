package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/admission"
	"github.com/kentrasecurity/periscope/internal/controller"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/observation"
	"github.com/kentrasecurity/periscope/internal/policy"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auth "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	mode := flag.String("mode", "", "investigator, executor or admission")
	policyPath := flag.String("policy", "/config/policy.json", "administrator policy")
	kubeconfig := flag.String("kubeconfig", "", "explicit development ServiceAccount kubeconfig; never defaults to user config")
	identity := flag.String("identity", "", "required authenticated ServiceAccount username")
	investigator := flag.String("investigator-user", "", "fixed investigator ServiceAccount username")
	executorUser := flag.String("executor-user", "", "fixed executor ServiceAccount username")
	provider := flag.String("provider", "openai", "openai or anthropic")
	model := flag.String("model", "", "provider model (default gpt-6-luna for openai, claude-opus-5-5 for anthropic)")
	providerAPI := flag.String("provider-api", "", "OpenAI API: responses or chat-completions; default based on model")
	reasoningEffort := flag.String("reasoning-effort", "", "OpenAI Responses reasoning effort (none, low, medium, high) or Anthropic effort (low, medium, high)")
	outputTokens := flag.Int("max-output-tokens", 16000, "bounded completion including reasoning and thinking tokens")
	baseURL := flag.String("base-url", "", "provider base URL (default: the provider's public API)")
	key := flag.String("api-key-file", "/credentials/api-key", "mounted provider Secret key")
	observationsPath := flag.String("observations", "/config/observations.json", "owner-configured optional observation sources")
	runbooksPath := flag.String("runbooks", "", "optional administrator-mounted reviewed runbooks JSON")
	tlsCert := flag.String("tls-cert", "/tls/tls.crt", "admission serving certificate")
	tlsKey := flag.String("tls-key", "/tls/tls.key", "admission serving private key")
	listen := flag.String("listen", ":8443", "admission HTTPS address")
	probe := flag.String("probe-listen", ":8080", "health HTTP address")
	workers := flag.Int("workers", 4, "tasks reconciled concurrently; one task is never reconciled twice at once")
	reconcileTimeout := flag.Duration("reconcile-timeout", 0, "maximum time for one reconcile (default 15m investigator, 2m executor)")
	flag.Parse()
	if *mode != "investigator" && *mode != "executor" && *mode != "admission" {
		return fmt.Errorf("explicit supported mode required")
	}
	if *identity == "" {
		return fmt.Errorf("expected ServiceAccount identity required")
	}
	f, err := os.Open(*policyPath)
	if err != nil {
		return err
	}
	p, err := policy.Load(f)
	f.Close()
	if err != nil {
		return err
	}
	var config *rest.Config
	if *kubeconfig == "" {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	}
	if err != nil {
		return err
	}
	// Authenticate before any reconciliation; an accidental administrator config is rejected.
	authentication, err := auth.NewForConfig(config)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	checkCtx, done := context.WithTimeout(ctx, 30*time.Second)
	who, err := authentication.SelfSubjectReviews().Create(checkCtx, &authv1.SelfSubjectReview{}, metav1.CreateOptions{})
	done()
	if err != nil {
		return fmt.Errorf("identity verification unavailable: %w", err)
	}
	if who.Status.UserInfo.Username != *identity || len(*identity) < 22 || (*identity)[:22] != "system:serviceaccount:" {
		return fmt.Errorf("authenticated identity does not match expected ServiceAccount")
	}
	client, err := kube.New(config)
	if err != nil {
		return err
	}
	var ready atomic.Bool
	health := http.NewServeMux()
	health.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	health.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	probes := &http.Server{Addr: *probe, Handler: health, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if e := probes.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			log.Printf("probe listener failed")
			cancel()
		}
	}()
	defer probes.Close()
	var configured struct {
		Prometheus *observation.PrometheusConfig `json:"prometheus"`
		Network    *observation.NetworkConfig    `json:"network"`
	}
	if raw, err := os.ReadFile(*observationsPath); err == nil {
		if len(raw) > 1<<20 || json.Unmarshal(raw, &configured) != nil {
			return fmt.Errorf("invalid observations configuration")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	var metrics observation.Tool
	var network *observation.Network
	if configured.Prometheus != nil {
		metrics, err = observation.NewPrometheus(*configured.Prometheus)
		if err != nil {
			return err
		}
	}
	if configured.Network != nil {
		network, err = observation.NewNetwork(*configured.Network)
		if err != nil {
			return err
		}
	}
	if network != nil {
		network.Reader = client
	}
	checker := executor.CheckEvaluator{Reader: client, Pods: client, Metrics: metrics}
	if network != nil {
		checker.Probe = network
	}
	if *mode == "admission" {
		if *investigator == "" || *executorUser == "" || *identity == *investigator || *identity == *executorUser {
			return fmt.Errorf("three distinct configured identities required")
		}
		validator := &admission.Validator{Checker: checker, Backend: client, Policy: p, InvestigatorUser: *investigator, ExecutorUser: *executorUser}
		server := &http.Server{Addr: *listen, Handler: validator, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, MaxHeaderBytes: 8192}
		go func() { <-ctx.Done(); server.Close() }()
		ready.Store(true)
		err = server.ListenAndServeTLS(*tlsCert, *tlsKey)
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
	if *mode == "executor" {
		ex := &executor.Executor{Checker: checker, Backend: client, Policy: p}
		return controller.RunQueue(ctx, client.Dynamic, p.Namespaces, ex.Reconcile, func() { ready.Store(true) }, queueOptions(*workers, *reconcileTimeout, 2*time.Minute))
	}
	llmClient, err := llm.New(llm.Config{Provider: *provider, API: *providerAPI, ReasoningEffort: *reasoningEffort, MaxOutputTokens: *outputTokens, Model: *model, BaseURL: *baseURL, APIKeyFile: *key})
	if err != nil {
		return err
	}
	var books []evidence.Runbook
	if *runbooksPath != "" {
		data, err := os.ReadFile(*runbooksPath)
		if err != nil {
			return err
		}
		if len(data) > 1<<20 {
			return fmt.Errorf("runbook file too large")
		}
		if err = json.Unmarshal(data, &books); err != nil {
			return fmt.Errorf("invalid runbooks JSON")
		}
	}
	inv := &controller.Investigator{Backend: client, Model: llmClient, Policy: p, Collector: evidence.Collector{Reader: client, Policy: p, MaxToolCalls: 30, Runbooks: books}}
	if metrics != nil || network != nil || len(books) > 0 {
		inv.ConfigureTools = func(r *observation.Registry) {
			if len(books) > 0 {
				r.Register(observation.ReviewedRunbooks{Books: books})
			}
			if metrics != nil {
				r.Register(metrics)
			}
			if network != nil {
				r.Register(network)
			}
		}
	}
	inv.Checker = checker
	return controller.RunQueue(ctx, client.Dynamic, p.Namespaces, inv.Reconcile, func() { ready.Store(true) }, queueOptions(*workers, *reconcileTimeout, 15*time.Minute))
}

func queueOptions(workers int, timeout, fallback time.Duration) controller.QueueOptions {
	if timeout == 0 {
		timeout = fallback
	}
	return controller.QueueOptions{Workers: workers, Timeout: timeout}
}
