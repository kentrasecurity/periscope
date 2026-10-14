package policy

import (
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"io"
	"strings"
)

type ValueRule struct {
	Values    []any    `json:"values,omitempty"`
	Minimum   *float64 `json:"minimum,omitempty"`
	Maximum   *float64 `json:"maximum,omitempty"`
	Pattern   string   `json:"pattern,omitempty"`
	MaxLength int      `json:"maxLength,omitempty"`
}
type Capability struct {
	APIVersion      string               `json:"apiVersion"`
	Kind            string               `json:"kind"`
	Resource        string               `json:"resource"`
	Namespace       string               `json:"namespace"`
	Names           []string             `json:"names"`
	Types           []string             `json:"types"`
	Paths           map[string]ValueRule `json:"paths,omitempty"`
	CreateObject    map[string]any       `json:"createObject,omitempty"`
	Risk            string               `json:"risk"`
	RequireApproval bool                 `json:"requireApproval"`
	HealthURL       string               `json:"healthURL,omitempty"`
}
type ReadRule struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Resource   string   `json:"resource"`
	Namespace  string   `json:"namespace"`
	Names      []string `json:"names,omitempty"`
	DataKeys   []string `json:"dataKeys,omitempty"`
}
type Config struct {
	CoordinationNamespace string            `json:"coordinationNamespace,omitempty"`
	Authorization         string            `json:"authorization,omitempty"`
	HealthURLs            map[string]string `json:"healthURLs,omitempty"`
	Namespaces            []string          `json:"namespaces"`
	ReadRules             []ReadRule        `json:"readRules"`
	Capabilities          []Capability      `json:"capabilities"`
	Repairs               Repairs           `json:"repairs,omitzero"`
	Experimental          Experimental      `json:"experimental,omitzero"`
}

// Experimental features are off by default and may change.
type Experimental struct {
	// ApplicationErrors opens incidents for otherwise healthy workloads whose
	// recent logs show errors with a common Kubernetes-side cause, such as a
	// NetworkPolicy blocking a dependency.
	ApplicationErrors bool `json:"applicationErrors,omitempty"`
}

// Repairs opts into repairs that are refused by default because they handle
// credentials or storage. RBAC must grant the matching verbs as well.
type Repairs struct {
	Secrets SecretRepairs  `json:"secrets,omitzero"`
	Storage StorageRepairs `json:"storage,omitzero"`
}

// SecretRepairs lets plans create a missing Secret whose values the executor
// fills in: random bytes ("generate") or a copy of an allowed source Secret
// ("fromSource"). The model never writes or sees a value.
type SecretRepairs struct {
	Create  string   `json:"create,omitempty"`
	Sources []string `json:"sources,omitempty"`
}

// StorageRepairs allows recreating PersistentVolumeClaims that never bound
// (they hold no data) and growing a claim's storage request.
type StorageRepairs struct {
	ReplaceUnboundClaims bool `json:"replaceUnboundClaims,omitempty"`
	ExpandClaims         bool `json:"expandClaims,omitempty"`
}

const (
	SecretsFromSource = "fromSource"
	SecretsGenerate   = "generate"
)

// SecretCreation reports whether plans may create Secrets in mode.
func (c Config) SecretCreation(mode string) bool {
	return c.Repairs.Secrets.Create == mode || c.Repairs.Secrets.Create == SecretsGenerate+"+"+SecretsFromSource
}

func Load(r io.Reader) (Config, error) {
	var c Config
	d := json.NewDecoder(io.LimitReader(r, 1024*1024))
	d.DisallowUnknownFields()
	if e := d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return c, fmt.Errorf("policy must contain exactly one JSON object")
	}
	for _, ns := range c.Namespaces {
		if ns == "" || ns == "*" {
			return c, fmt.Errorf("explicit enrolled namespaces required")
		}
	}
	if c.Authorization != "" && c.Authorization != "LegacyCatalog" && c.Authorization != "RBAC" {
		return c, fmt.Errorf("unknown authorization mode")
	}
	if c.CoordinationNamespace != "" && !contains(c.Namespaces, c.CoordinationNamespace) {
		return c, fmt.Errorf("coordination namespace must be enrolled")
	}
	switch c.Repairs.Secrets.Create {
	case "", "none", SecretsGenerate, SecretsFromSource, SecretsGenerate + "+" + SecretsFromSource:
	default:
		return c, fmt.Errorf("repairs.secrets.create must be none, generate, fromSource or generate+fromSource")
	}
	if len(c.Repairs.Secrets.Sources) > 32 || len(c.Repairs.Secrets.Sources) > 0 && !c.SecretCreation(SecretsFromSource) {
		return c, fmt.Errorf("repairs.secrets.sources requires create fromSource (at most 32)")
	}
	for _, s := range c.Repairs.Secrets.Sources {
		if s == "" || strings.ContainsAny(s, "*/") {
			return c, fmt.Errorf("repairs.secrets.sources must name Secrets explicitly")
		}
	}
	if (c.Repairs.Secrets.Create != "" && c.Repairs.Secrets.Create != "none" || c.Repairs.Storage != StorageRepairs{}) && !c.RBAC() {
		return c, fmt.Errorf("repairs require authorization RBAC")
	}
	if c.RBAC() {
		return c, nil
	}
	for _, r := range c.ReadRules {
		if !contains(c.Namespaces, r.Namespace) || r.APIVersion == "" || r.Kind == "" || dangerous(r.Kind) || !SafeResource(r.Resource) {
			return c, fmt.Errorf("invalid or dangerous read rule")
		}
	}
	for _, v := range c.Capabilities {
		if dangerous(v.Kind) || !SafeResource(v.Resource) {
			return c, fmt.Errorf("dangerous capability resource")
		}
		if v.APIVersion == "" || v.Kind == "" || v.Resource == "" || len(v.Names) == 0 || len(v.Types) == 0 || v.Namespace == "" {
			return c, fmt.Errorf("capability requires explicit API, resource, namespace, names and types")
		}
		if !contains(c.Namespaces, v.Namespace) {
			return c, fmt.Errorf("capability namespace is not enrolled")
		}
		for _, n := range v.Names {
			if n == "" || n == "*" {
				return c, fmt.Errorf("wildcard/empty target name forbidden")
			}
		}
	}
	return c, nil
}
func SafeResource(resource string) bool {
	if resource == "" || strings.ContainsAny(resource, "*/") {
		return false
	}
	switch resource {
	case "secrets", "serviceaccounts", "roles", "rolebindings", "clusterroles", "clusterrolebindings", "customresourcedefinitions", "validatingwebhookconfigurations", "mutatingwebhookconfigurations", "validatingadmissionpolicies", "validatingadmissionpolicybindings", "certificatesigningrequests", "tokenreviews", "subjectaccessreviews", "selfsubjectaccessreviews", "selfsubjectrulesreviews", "localsubjectaccessreviews":
		return false
	}
	return true
}
func PolicyDigest(c Config) string { s, _ := api.Hash(c); return s }
func contains(items []string, value string) bool {
	for _, v := range items {
		if v == value {
			return true
		}
	}
	return false
}

func (c Config) RBAC() bool { return c.Authorization == "RBAC" }
func (c Config) HealthURL(t api.TargetRef) string {
	return c.HealthURLs[t.Namespace+"/"+t.Kind+"/"+t.Name]
}
func (c Config) ReadAllowed(t api.TargetRef) bool {
	if c.RBAC() {
		return contains(c.Namespaces, t.Namespace)
	}
	if dangerous(t.Kind) {
		return false
	}
	for _, r := range c.ReadRules {
		if r.APIVersion == t.APIVersion && r.Kind == t.Kind && r.Namespace == t.Namespace && (len(r.Names) == 0 || contains(r.Names, t.Name)) {
			return true
		}
	}
	return false
}
func (c Config) Find(a api.Action) (Capability, error) {
	if c.RBAC() {
		if !contains(c.Namespaces, a.Target.Namespace) {
			return Capability{}, fmt.Errorf("target outside watched namespaces")
		}
		return Capability{APIVersion: a.Target.APIVersion, Kind: a.Target.Kind, Namespace: a.Target.Namespace, Names: []string{a.Target.Name}, Types: []string{a.Type}, Risk: "disruptive", RequireApproval: true, HealthURL: c.HealthURL(a.Target)}, nil
	}
	for _, v := range c.Capabilities {
		if v.APIVersion == a.Target.APIVersion && v.Kind == a.Target.Kind && v.Namespace == a.Target.Namespace && contains(v.Names, a.Target.Name) && contains(v.Types, a.Type) {
			return v, nil
		}
	}
	return Capability{}, fmt.Errorf("no capability authorizes %s on %s/%s", a.Type, a.Target.Namespace, a.Target.Name)
}
