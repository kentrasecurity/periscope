package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	authz "k8s.io/client-go/kubernetes/typed/authorization/v1"
	coord "k8s.io/client-go/kubernetes/typed/coordination/v1"
	core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"strings"
)

var TaskGVR = schema.GroupVersionResource{Group: api.Group, Version: api.Version, Resource: "agenttasks"}
var PlanGVR = schema.GroupVersionResource{Group: api.Group, Version: api.Version, Resource: "actionplans"}
var ApprovalGVR = schema.GroupVersionResource{Group: api.Group, Version: api.Version, Resource: "actionapprovals"}

type Client struct {
	Authz     authz.AuthorizationV1Interface
	Dynamic   dynamic.Interface
	Core      core.CoreV1Interface
	Discovery discovery.DiscoveryInterface
	Mapper    meta.RESTMapper
	Coord     coord.CoordinationV1Interface
}

func New(config *rest.Config) (*Client, error) {
	copy := rest.CopyConfig(config)
	copy.Timeout = 30_000_000_000
	if copy.QPS <= 0 {
		copy.QPS = 20
	}
	if copy.Burst <= 0 {
		copy.Burst = 100
	}
	d, e := dynamic.NewForConfig(copy)
	if e != nil {
		return nil, e
	}
	c, e := core.NewForConfig(copy)
	if e != nil {
		return nil, e
	}
	dis, e := discovery.NewDiscoveryClientForConfig(copy)
	if e != nil {
		return nil, e
	}
	leases, e := coord.NewForConfig(copy)
	if e != nil {
		return nil, e
	}
	authorization, e := authz.NewForConfig(copy)
	if e != nil {
		return nil, e
	}
	return &Client{Authz: authorization, Dynamic: d, Core: c, Coord: leases, Discovery: dis, Mapper: restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dis))}, nil
}
func (c *Client) Mapping(t api.TargetRef) (*meta.RESTMapping, error) {
	if c.Mapper == nil {
		return nil, fmt.Errorf("API mapper unavailable")
	}
	gv, e := schema.ParseGroupVersion(t.APIVersion)
	if e != nil {
		return nil, e
	}
	m, e := c.Mapper.RESTMapping(schema.GroupKind{Group: gv.Group, Kind: t.Kind}, gv.Version)
	if e != nil {
		return nil, e
	}
	if m.Scope.Name() != meta.RESTScopeNameNamespace || t.Namespace == "" {
		return nil, fmt.Errorf("cluster-scoped execution is not implemented by this client")
	}
	return m, nil
}

// StorageClassNames is the only cluster-scoped read: names of StorageClasses,
// so a claim with a misspelled class is replaced with the intended one.
func (c *Client) StorageClassNames(ctx context.Context) ([]string, error) {
	items, err := c.Dynamic.Resource(schema.GroupVersionResource{Group: "storage.k8s.io", Version: "v1", Resource: "storageclasses"}).List(ctx, metav1.ListOptions{Limit: listPageSize})
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, item := range items.Items {
		names = append(names, item.GetName())
	}
	return names, nil
}
func (c *Client) Get(ctx context.Context, t api.TargetRef) (*unstructured.Unstructured, error) {
	m, e := c.Mapping(t)
	if e != nil {
		return nil, e
	}
	return c.Dynamic.Resource(m.Resource).Namespace(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
}
func (c *Client) List(ctx context.Context, version, kind, namespace, selector string) ([]*unstructured.Unstructured, error) {
	m, e := c.Mapping(api.TargetRef{APIVersion: version, Kind: kind, Namespace: namespace})
	if e != nil {
		return nil, e
	}
	// Paginate up to a bound: the API returns objects in key order, so a single
	// short page would drop the newest Events and most Pods of a busy namespace.
	options := metav1.ListOptions{Limit: listPageSize}
	if kind == "Event" {
		options.FieldSelector = selector
	} else {
		options.LabelSelector = selector
	}
	out := []*unstructured.Unstructured{}
	for {
		items, e := c.Dynamic.Resource(m.Resource).Namespace(namespace).List(ctx, options)
		if e != nil {
			return nil, e
		}
		for n := range items.Items {
			out = append(out, items.Items[n].DeepCopy())
		}
		options.Continue = items.GetContinue()
		if options.Continue == "" || len(out) >= maxListItems {
			return out, nil
		}
	}
}

const (
	listPageSize = 250
	maxListItems = 1000
)

func (c *Client) Logs(ctx context.Context, namespace, pod, container string, previous bool, limit int64) (string, error) {
	if limit < 1 || limit > api.MaxLogBytes {
		return "", fmt.Errorf("invalid log size")
	}
	tail := int64(200)
	data, e := c.Core.Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{Container: container, Previous: previous, LimitBytes: &limit, TailLines: &tail}).DoRaw(ctx)
	return string(data), e
}

// RecentLogs returns what a container logged in the last sinceSeconds,
// bounded like Logs.
func (c *Client) RecentLogs(ctx context.Context, namespace, pod, container string, sinceSeconds int64) (string, error) {
	limit, tail := int64(api.MaxLogBytes), int64(500)
	data, e := c.Core.Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{Container: container, SinceSeconds: &sinceSeconds, LimitBytes: &limit, TailLines: &tail}).DoRaw(ctx)
	return string(data), e
}

func (c *Client) DescribeAPI(ctx context.Context, t api.TargetRef) (string, error) {
	m, e := c.Mapping(t)
	if e != nil {
		return "", e
	}
	result := map[string]any{"apiVersion": t.APIVersion, "kind": t.Kind, "resource": m.Resource.Resource, "scope": "Namespaced"}
	if c.Discovery != nil {
		if v, err := c.Discovery.ServerVersion(); err == nil {
			result["kubernetesVersion"] = v.GitVersion
		}
		paths, err := c.Discovery.OpenAPIV3().Paths()
		if err == nil {
			key := "apis/" + t.APIVersion
			if !strings.Contains(t.APIVersion, "/") {
				key = "api/" + t.APIVersion
			}
			if group, ok := paths[key]; ok {
				raw, err := group.Schema("application/json")
				if err == nil && len(raw) <= 8<<20 {
					var document map[string]any
					if json.Unmarshal(raw, &document) == nil {
						schemas, _, _ := unstructured.NestedMap(document, "components", "schemas")
						for _, entry := range schemas {
							object, ok := entry.(map[string]any)
							if !ok {
								continue
							}
							gvks, ok := object["x-kubernetes-group-version-kind"].([]any)
							if !ok {
								continue
							}
							for _, value := range gvks {
								gvk, ok := value.(map[string]any)
								if !ok {
									continue
								}
								gv, _ := schema.ParseGroupVersion(t.APIVersion)
								if gvk["kind"] == t.Kind && gvk["version"] == gv.Version && gvk["group"] == gv.Group {
									result["schema"] = object
								}
							}
						}
					}
				}
			}
		}
	}
	raw, e := json.Marshal(result)
	return string(raw), e
}

func (c *Client) GetTask(ctx context.Context, namespace, name string) (*Task, error) {
	u, e := c.Dynamic.Resource(TaskGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if e != nil {
		return nil, e
	}
	return ParseTask(u)
}
func (c *Client) SaveTaskStatus(ctx context.Context, t *Task) error {
	u := t.Object.DeepCopy()
	u.Object["status"] = JSONMap(t.Status)
	updated, e := c.Dynamic.Resource(TaskGVR).Namespace(u.GetNamespace()).UpdateStatus(ctx, u, metav1.UpdateOptions{FieldValidation: "Strict"})
	if e == nil {
		t.Object = updated
	}
	return e
}
func (c *Client) GetPlan(ctx context.Context, namespace, name string) (*Plan, error) {
	u, e := c.Dynamic.Resource(PlanGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if e != nil {
		return nil, e
	}
	return ParsePlan(u)
}
func (c *Client) CreatePlan(ctx context.Context, namespace, name string, s api.PlanSpec) (*Plan, error) {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.Group + "/" + api.Version, "kind": "ActionPlan", "metadata": map[string]any{"name": name, "namespace": namespace}, "spec": JSONMap(s)}}
	created, e := c.Dynamic.Resource(PlanGVR).Namespace(namespace).Create(ctx, u, metav1.CreateOptions{FieldValidation: "Strict"})
	if e != nil {
		return nil, e
	}
	return ParsePlan(created)
}
func (c *Client) SavePlanStatus(ctx context.Context, p *Plan) error {
	u := p.Object.DeepCopy()
	u.Object["status"] = JSONMap(p.Status)
	updated, e := c.Dynamic.Resource(PlanGVR).Namespace(u.GetNamespace()).UpdateStatus(ctx, u, metav1.UpdateOptions{FieldValidation: "Strict"})
	if e == nil {
		p.Object = updated
	}
	return e
}
func (c *Client) Approvals(ctx context.Context, namespace string) ([]*Approval, error) {
	var out []*Approval
	next := ""
	for {
		list, e := c.Dynamic.Resource(ApprovalGVR).Namespace(namespace).List(ctx, metav1.ListOptions{Limit: 128, Continue: next})
		if e != nil {
			return nil, e
		}
		for n := range list.Items {
			u := list.Items[n].DeepCopy()
			a := &Approval{Object: u}
			if e = Decode(u.Object["spec"], &a.Spec); e != nil {
				return nil, e
			}
			out = append(out, a)
		}
		next = list.GetContinue()
		if next == "" {
			break
		}
		if len(out) > 1024 {
			return nil, fmt.Errorf("approval listing limit exceeded")
		}
	}
	return out, nil
}

func (c *Client) ListPlans(ctx context.Context, namespace string) ([]*Plan, error) {
	var out []*Plan
	next := ""
	for {
		list, e := c.Dynamic.Resource(PlanGVR).Namespace(namespace).List(ctx, metav1.ListOptions{Limit: 128, Continue: next})
		if e != nil {
			return nil, e
		}
		for n := range list.Items {
			p, e := ParsePlan(list.Items[n].DeepCopy())
			if e != nil {
				return nil, e
			}
			out = append(out, p)
		}
		next = list.GetContinue()
		if next == "" {
			return out, nil
		}
		if len(out) > 1024 {
			return nil, fmt.Errorf("plan listing limit exceeded")
		}
	}
}

func (c *Client) CreateApproval(ctx context.Context, ns, name string, s api.ApprovalSpec) (*Approval, error) {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.Group + "/" + api.Version, "kind": "ActionApproval", "metadata": map[string]any{"name": name, "namespace": ns, "labels": map[string]any{api.Group + "/plan-uid": s.PlanUID}}, "spec": JSONMap(s)}}
	created, err := c.Dynamic.Resource(ApprovalGVR).Namespace(ns).Create(ctx, u, metav1.CreateOptions{FieldValidation: "Strict"})
	if err != nil {
		return nil, err
	}
	var spec api.ApprovalSpec
	if err = Decode(created.Object["spec"], &spec); err != nil {
		return nil, err
	}
	return &Approval{Object: created, Spec: spec}, nil
}

func (c *Client) NamespacedResources(ctx context.Context) ([]api.ResourceSelector, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	groups, err := c.Discovery.ServerPreferredNamespacedResources()
	if err != nil {
		return nil, fmt.Errorf("namespace resource discovery incomplete: %w", err)
	}
	out := []api.ResourceSelector{}
	for _, group := range groups {
		for _, resource := range group.APIResources {
			if !resource.Namespaced || strings.Contains(resource.Name, "/") {
				continue
			}
			listed := false
			for _, verb := range resource.Verbs {
				if verb == "list" {
					listed = true
				}
			}
			if listed {
				out = append(out, api.ResourceSelector{APIVersion: group.GroupVersion, Kind: resource.Kind})
			}
			if len(out) > 4096 {
				return nil, fmt.Errorf("resource discovery limit exceeded")
			}
		}
	}
	return out, nil
}
