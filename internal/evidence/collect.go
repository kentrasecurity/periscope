package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/policy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sort"
	"strings"
	"time"
)

type Reader interface {
	Get(context.Context, api.TargetRef) (*unstructured.Unstructured, error)
	List(context.Context, string, string, string, string) ([]*unstructured.Unstructured, error)
	Logs(context.Context, string, string, string, bool, int64) (string, error)
	DescribeAPI(context.Context, api.TargetRef) (string, error)
}
type Bundle struct {
	Target    *unstructured.Unstructured `json:"-"`
	Evidence  []api.Evidence             `json:"evidence"`
	Gaps      []string                   `json:"gaps"`
	ToolCalls int                        `json:"toolCalls"`
	Absent    bool                       `json:"absent,omitempty"`
}
type Collector struct {
	Scope        *api.Scope
	Reader       Reader
	Policy       policy.Config
	MaxToolCalls int
	Runbooks     []Runbook
}

func (c Collector) Collect(ctx context.Context, t api.TargetRef, namespace string) (Bundle, error) {
	b := Bundle{}
	if t.Namespace == "" {
		t.Namespace = namespace
	}
	if t.Namespace != namespace || !c.Policy.ReadAllowed(t) || c.Scope != nil && !c.Scope.Contains(t) {
		return b, fmt.Errorf("target outside evidence read scope")
	}
	budget := c.MaxToolCalls
	if budget < 1 || budget > 100 {
		return b, fmt.Errorf("invalid tool budget")
	}
	take := func() bool {
		if b.ToolCalls >= budget {
			b.Gaps = append(b.Gaps, "tool-call budget exhausted")
			return false
		}
		b.ToolCalls++
		return true
	}
	add := func(source, text string) {
		// Leave half of the evidence list for the model's own tool reads.
		if len(b.Evidence) >= api.MaxEvidenceItems/2 {
			b.Gaps = append(b.Gaps, "seed evidence truncated: "+source)
			return
		}
		text = Bound(Redact(text), 8192)
		h, _ := api.Hash(text)
		b.Evidence = append(b.Evidence, api.Evidence{ID: fmt.Sprintf("evidence-%d", len(b.Evidence)+1), Source: source, CollectedAt: time.Now().UTC(), Hash: h, Content: text})
	}
	if !take() {
		return b, fmt.Errorf("no target read budget")
	}
	u, e := c.Reader.Get(ctx, t)
	if e != nil {
		if apierrors.IsNotFound(e) {
			b.Absent = true
			b.Target = &unstructured.Unstructured{Object: map[string]any{"apiVersion": t.APIVersion, "kind": t.Kind, "metadata": map[string]any{"name": t.Name, "namespace": namespace}}}
			add("target:"+namespace+"/"+t.Name, "The authorized target is absent (Kubernetes NotFound).")
			return b, nil
		}
		return b, fmt.Errorf("target read unavailable: %w", e)
	}
	if c.Scope != nil && !c.Scope.Matches(t, u) {
		return b, fmt.Errorf("target no longer matches scope")
	}
	b.Target = u
	projection := Project(u, c.Policy)
	raw, _ := json.Marshal(projection)
	add("target:"+t.Namespace+"/"+t.Name, string(raw))
	ownerObject := u
	seen := map[string]bool{string(u.GetUID()): true}
	for depth := 0; depth < 4; depth++ {
		owners := ownerObject.GetOwnerReferences()
		if len(owners) == 0 {
			break
		}
		owner := owners[0]
		for _, candidate := range owners {
			if candidate.Controller != nil && *candidate.Controller {
				owner = candidate
				break
			}
		}
		ref := api.TargetRef{APIVersion: owner.APIVersion, Kind: owner.Kind, Namespace: namespace, Name: owner.Name, UID: string(owner.UID)}
		if seen[ref.UID] {
			b.Gaps = append(b.Gaps, "owner traversal cycle")
			break
		}
		seen[ref.UID] = true
		if !c.Policy.ReadAllowed(ref) || c.Scope != nil && !c.Scope.Contains(ref) {
			b.Gaps = append(b.Gaps, "owner context unavailable by policy")
			break
		}
		if !take() {
			break
		}
		parent, err := c.Reader.Get(ctx, ref)
		if err != nil || string(parent.GetUID()) != ref.UID || c.Scope != nil && !c.Scope.Matches(ref, parent) {
			b.Gaps = append(b.Gaps, "owner context unavailable or identity changed")
			break
		}
		data, _ := json.Marshal(Project(parent, c.Policy))
		add("owner:"+namespace+"/"+owner.Name, string(data))
		ownerObject = parent
	}
	labels := u.GetLabels()
	application, version := labels["app.kubernetes.io/name"], labels["app.kubernetes.io/version"]
	if application != "" && version != "" {
		for _, book := range Retrieve(c.Runbooks, Query{Namespace: namespace, Application: application, Version: version, Now: time.Now().UTC()}) {
			add("runbook:"+book.ID+"@"+book.Revision, book.Text)
		}
	}
	if take() {
		description, err := c.Reader.DescribeAPI(ctx, t)
		if err != nil {
			b.Gaps = append(b.Gaps, "API schema/discovery unavailable")
		} else {
			add("api-discovery", description)
		}
	}
	// Events are grouped into one evidence item per query, newest first, so the
	// seed bundle stays well below the 32-item evidence bound and leaves room for
	// the model's own tool reads.
	eventTarget := api.TargetRef{APIVersion: "v1", Kind: "Event", Namespace: namespace}
	eventsAllowed := c.Policy.ReadAllowed(eventTarget)
	if eventsAllowed && take() {
		events, err := c.Reader.List(ctx, "v1", "Event", namespace, "involvedObject.uid="+string(u.GetUID()))
		if err != nil {
			b.Gaps = append(b.Gaps, "Events unavailable: "+Bound(Redact(err.Error()), 512))
		} else {
			lines := EventLines(events, func(e *unstructured.Unstructured) bool {
				return Field(e, "involvedObject", "uid") == string(u.GetUID())
			}, maxEventLines)
			if len(lines) > 0 {
				add("events:"+u.GetKind()+"/"+u.GetName(), strings.Join(lines, "\n"))
			}
		}
	} else {
		b.Gaps = append(b.Gaps, "Events unavailable by policy or budget")
	}
	pods := []*unstructured.Unstructured{}
	if u.GetKind() == "Pod" {
		pods = append(pods, u)
	} else if selector := podSelector(u); selector != "" {
		podTarget := api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: namespace}
		if c.Policy.ReadAllowed(podTarget) && take() {
			items, err := c.Reader.List(ctx, "v1", "Pod", namespace, selector)
			if err != nil {
				b.Gaps = append(b.Gaps, "owned Pods unavailable")
			} else {
				pods = items
			}
		}
	}
	// Failing Pods carry the diagnosis; sample them first and fetch logs only
	// for them (or for one healthy Pod when none is failing).
	sort.SliceStable(pods, func(a, b int) bool { return !podReady(pods[a]) && podReady(pods[b]) })
	related := map[string]bool{}
	logged := 0
	for i, pod := range pods {
		if i >= maxSampledPods {
			b.Gaps = append(b.Gaps, fmt.Sprintf("Pod sample limited to %d of %d", maxSampledPods, len(pods)))
			break
		}
		podRef := api.TargetRef{APIVersion: "v1", Kind: "Pod", Namespace: namespace, Name: pod.GetName()}
		if !c.Policy.ReadAllowed(podRef) || c.Scope != nil && !c.Scope.Matches(podRef, pod) {
			continue
		}
		if pod.GetUID() != u.GetUID() {
			related[string(pod.GetUID())] = true
		}
		for _, owner := range pod.GetOwnerReferences() {
			owned := api.TargetRef{APIVersion: owner.APIVersion, Kind: owner.Kind, Namespace: namespace, Name: owner.Name}
			if string(owner.UID) != string(u.GetUID()) && (c.Scope == nil || c.Scope.Contains(owned)) {
				related[string(owner.UID)] = true
			}
		}
		if pod.GetUID() != u.GetUID() {
			podJSON, _ := json.Marshal(Project(pod, c.Policy))
			add("pod:"+pod.GetName(), string(podJSON))
		}
		if logged >= maxLoggedPods || logged > 0 && podReady(pod) {
			continue
		}
		logged++
		for _, name := range containerNames(pod) {
			sections := []string{}
			for _, previous := range []bool{false, true} {
				if !take() {
					break
				}
				log, err := c.Reader.Logs(ctx, namespace, pod.GetName(), name, previous, int64(api.MaxLogBytes))
				label := "current"
				if previous {
					label = "previous (last terminated container)"
				}
				switch {
				case err != nil && previous:
					// No previous container is normal for Pods that never restarted.
				case err != nil:
					b.Gaps = append(b.Gaps, fmt.Sprintf("logs unavailable: %s/%s", pod.GetName(), name))
				case strings.TrimSpace(log) == "":
					sections = append(sections, "== "+label+" ==\n(empty)")
				default:
					sections = append(sections, "== "+label+" ==\n"+BoundTail(Redact(log), 3900))
				}
			}
			if len(sections) > 0 {
				add(fmt.Sprintf("logs:%s/%s", pod.GetName(), name), strings.Join(sections, "\n"))
			}
		}
	}
	// Scheduling, mount, image pull and quota failures are reported as Warning
	// Events on the Pods and their ReplicaSets, not on the workload itself.
	// Namespace-wide Warnings also reveal causes outside the owner chain, such
	// as quota, storage provisioning or a failing dependency.
	if eventsAllowed && take() {
		events, err := c.Reader.List(ctx, "v1", "Event", namespace, "type=Warning")
		if err != nil {
			b.Gaps = append(b.Gaps, "namespace Warning Events unavailable")
		} else {
			isRelated := func(e *unstructured.Unstructured) bool {
				return Field(e, "type") == "Warning" && related[Field(e, "involvedObject", "uid")]
			}
			if lines := EventLines(events, isRelated, maxEventLines); len(lines) > 0 {
				add("events:related-warnings", strings.Join(lines, "\n"))
			}
			others := EventLines(events, func(e *unstructured.Unstructured) bool {
				uid := Field(e, "involvedObject", "uid")
				return Field(e, "type") == "Warning" && !related[uid] && uid != string(u.GetUID()) && EventInScope(c.Scope, e)
			}, maxEventLines)
			if len(others) > 0 {
				add("events:namespace-warnings", strings.Join(others, "\n"))
			}
		}
	}
	return b, nil
}

const (
	maxEventLines  = 40
	maxSampledPods = 6
	maxLoggedPods  = 3
)

// podSelector returns the label selector of a workload's Pods (matchLabels
// for controllers, the plain selector map for Services).
func podSelector(u *unstructured.Unstructured) string {
	labels, _, _ := unstructured.NestedStringMap(u.Object, "spec", "selector", "matchLabels")
	if u.GetKind() == "Service" {
		labels, _, _ = unstructured.NestedStringMap(u.Object, "spec", "selector")
	}
	if len(labels) == 0 {
		return ""
	}
	parts := []string{}
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func podReady(pod *unstructured.Unstructured) bool {
	conditions, _, _ := unstructured.NestedSlice(pod.Object, "status", "conditions")
	for _, c := range conditions {
		if m, ok := c.(map[string]any); ok && m["type"] == "Ready" {
			return m["status"] == "True"
		}
	}
	return false
}

func containerNames(pod *unstructured.Unstructured) []string {
	names := []string{}
	for _, group := range []string{"initContainers", "containers"} {
		containers, _, _ := unstructured.NestedSlice(pod.Object, "spec", group)
		for _, container := range containers {
			if m, ok := container.(map[string]any); ok {
				if name, _ := m["name"].(string); name != "" {
					names = append(names, name)
				}
			}
		}
	}
	return names
}

// Field returns a nested string field, or "" when absent.
func Field(u *unstructured.Unstructured, path ...string) string {
	value, _, _ := unstructured.NestedString(u.Object, path...)
	return value
}

// EventInScope reports whether an Event's involved object is inside the scope;
// a nil scope (single-target task) admits the whole enrolled namespace.
func EventInScope(s *api.Scope, event *unstructured.Unstructured) bool {
	if s == nil {
		return true
	}
	return s.Contains(api.TargetRef{APIVersion: Field(event, "involvedObject", "apiVersion"), Kind: Field(event, "involvedObject", "kind"), Namespace: event.GetNamespace(), Name: Field(event, "involvedObject", "name")})
}

// EventLines renders matching Events newest first, one line each.
func EventLines(events []*unstructured.Unstructured, keep func(*unstructured.Unstructured) bool, limit int) []string {
	matched := []*unstructured.Unstructured{}
	for _, e := range events {
		if keep(e) {
			matched = append(matched, e)
		}
	}
	sort.SliceStable(matched, func(a, b int) bool { return EventTime(matched[a]).After(EventTime(matched[b])) })
	lines := []string{}
	for _, e := range matched {
		if len(lines) == limit {
			lines = append(lines, fmt.Sprintf("(%d older Events omitted)", len(matched)-limit))
			break
		}
		lines = append(lines, eventText(e))
	}
	return lines
}

// EventTime is the most recent occurrence of an Event: series, lastTimestamp,
// eventTime, then creation time (events.k8s.io writers leave lastTimestamp empty).
func EventTime(e *unstructured.Unstructured) time.Time {
	for _, path := range [][]string{{"series", "lastObservedTime"}, {"lastTimestamp"}, {"eventTime"}, {"firstTimestamp"}} {
		if value := Field(e, path...); value != "" {
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
				if parsed, err := time.Parse(layout, value); err == nil {
					return parsed
				}
			}
		}
	}
	return e.GetCreationTimestamp().Time
}

func eventText(event *unstructured.Unstructured) string {
	count, _, _ := unstructured.NestedInt64(event.Object, "count")
	last := ""
	if at := EventTime(event); !at.IsZero() {
		last = at.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("%s %s on %s/%s (count %d, last %s): %s", Field(event, "type"), Field(event, "reason"), Field(event, "involvedObject", "kind"), Field(event, "involvedObject", "name"), count, last, Field(event, "message"))
}

// Project copies only explicitly selected metadata/status/spec fields; no annotations,
// env credentials, Secret references, arbitrary custom fields or unfiltered ConfigMaps.
func Project(u *unstructured.Unstructured, c policy.Config) map[string]any {
	if c.RBAC() {
		return projectRBAC(u)
	}
	result := map[string]any{"apiVersion": u.GetAPIVersion(), "kind": u.GetKind(), "metadata": map[string]any{"name": u.GetName(), "namespace": u.GetNamespace(), "uid": string(u.GetUID()), "generation": u.GetGeneration()}}
	status := map[string]any{}
	for _, field := range []string{"phase", "reason", "message", "conditions", "containerStatuses", "initContainerStatuses", "replicas", "readyReplicas", "availableReplicas", "observedGeneration"} {
		if v, ok, _ := unstructured.NestedFieldCopy(u.Object, "status", field); ok {
			status[field] = v
		}
	}
	if len(status) > 0 {
		result["status"] = status
	}
	if containers, ok, _ := unstructured.NestedSlice(u.Object, "spec", "template", "spec", "containers"); ok {
		result["containers"] = safeContainers(containers)
	} else if containers, ok, _ := unstructured.NestedSlice(u.Object, "spec", "containers"); ok {
		result["containers"] = safeContainers(containers)
	}
	for _, rule := range c.ReadRules {
		if rule.APIVersion == u.GetAPIVersion() && rule.Kind == u.GetKind() && rule.Namespace == u.GetNamespace() && (len(rule.Names) == 0 || in(rule.Names, u.GetName())) {
			data := map[string]any{}
			for _, key := range rule.DataKeys {
				if v, ok, _ := unstructured.NestedString(u.Object, "data", key); ok {
					data[key] = v
				}
			}
			if len(data) > 0 {
				result["data"] = data
			}
		}
	}
	// Administrator-declared repair fields are visible as values plus exact JSON paths.
	fields := map[string]any{}
	for _, cap := range c.Capabilities {
		if cap.APIVersion == u.GetAPIVersion() && cap.Kind == u.GetKind() && cap.Namespace == u.GetNamespace() && in(cap.Names, u.GetName()) {
			for path := range cap.Paths {
				if value, ok := Lookup(u.Object, path); ok {
					fields[path] = value
				}
			}
		}
	}
	if len(fields) > 0 {
		result["repairFields"] = fields
	}
	return result
}
func safeContainers(items []any) []any {
	var out []any
	for _, v := range items {
		if c, ok := v.(map[string]any); ok {
			m := map[string]any{}
			for _, k := range []string{"name", "image", "resources"} {
				if x, exists := c[k]; exists {
					m[k] = x
				}
			}
			out = append(out, m)
		}
	}
	return out
}
func in(items []string, s string) bool {
	for _, v := range items {
		if v == s {
			return true
		}
	}
	return false
}
