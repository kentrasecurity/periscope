package executor

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kentrasecurity/periscope/internal/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

// ReferenceKinds are kinds whose health depends on the objects they refer to;
// CheckReferences evaluates them with a namespace reader.
func ReferenceKinds(kind string) bool {
	switch kind {
	case "Service", "Ingress", "PodDisruptionBudget", "NetworkPolicy", "CronJob", "ConfigMap":
		return true
	}
	return false
}

// CheckReferences reports whether the objects u refers to exist and can serve
// it. The observation names what is broken, for the model and the report.
func CheckReferences(ctx context.Context, r PodReader, u *unstructured.Unstructured) (bool, string, string, error) {
	var problems []string
	var err error
	switch u.GetKind() {
	case "Service":
		healthy, fingerprint, err := CheckService(ctx, r, u)
		if err != nil || healthy {
			return healthy, fingerprint, "", err
		}
		selector, _, _ := unstructured.NestedStringMap(u.Object, "spec", "selector")
		observation := fmt.Sprintf("Service selector %s matches no Pod or workload template in namespace %s", labels.SelectorFromSet(selector), u.GetNamespace())
		if nearest := NearestBackend(ctx, r, u); nearest != "" {
			observation += "; nearest match: " + nearest
		}
		return false, fingerprint, observation, nil
	case "Ingress":
		problems, err = ingressProblems(ctx, r, u)
	case "PodDisruptionBudget":
		problems, err = selectorProblems(ctx, r, u, "PodDisruptionBudget selector", "spec", "selector")
	case "NetworkPolicy":
		problems, err = networkPolicyProblems(ctx, r, u)
	case "CronJob":
		problems, err = cronJobProblems(ctx, r, u)
	case "ConfigMap":
		problems, err = configMapProblems(ctx, r, u)
	default:
		return false, "", "", fmt.Errorf("no reference semantics for %s", u.GetKind())
	}
	if err != nil {
		return false, "", "", err
	}
	sort.Strings(problems)
	fingerprint, err := api.Hash([]any{string(u.GetUID()), u.GetGeneration(), problems})
	return len(problems) == 0, fingerprint, strings.Join(problems, "; "), err
}

func ingressProblems(ctx context.Context, r PodReader, u *unstructured.Unstructured) ([]string, error) {
	type backend struct {
		service string
		port    map[string]any
	}
	var backends []backend
	if s, ok, _ := unstructured.NestedMap(u.Object, "spec", "defaultBackend", "service"); ok {
		port, _, _ := unstructured.NestedMap(s, "port")
		backends = append(backends, backend{fmt.Sprint(s["name"]), port})
	}
	rules, _, _ := unstructured.NestedSlice(u.Object, "spec", "rules")
	for _, rule := range rules {
		paths, _, _ := unstructured.NestedSlice(rule.(map[string]any), "http", "paths")
		for _, path := range paths {
			if s, ok, _ := unstructured.NestedMap(path.(map[string]any), "backend", "service"); ok {
				port, _, _ := unstructured.NestedMap(s, "port")
				backends = append(backends, backend{fmt.Sprint(s["name"]), port})
			}
		}
	}
	if len(backends) == 0 {
		return nil, nil // resource backends and class defaults are not Service references
	}
	services, err := r.List(ctx, "v1", "Service", u.GetNamespace(), "")
	if err != nil {
		return nil, err
	}
	byName := map[string]*unstructured.Unstructured{}
	names := []string{}
	for _, s := range services {
		byName[s.GetName()] = s
		names = append(names, s.GetName())
	}
	problems := []string{}
	reported := map[string]bool{}
	for _, b := range backends {
		svc := byName[b.service]
		if svc == nil {
			p := fmt.Sprintf("Ingress backend Service %q does not exist", b.service)
			if near := nearestName(b.service, names); near != "" {
				p += fmt.Sprintf(" (nearest Service: %q)", near)
			}
			if !reported[p] {
				reported[p] = true
				problems = append(problems, p)
			}
			continue
		}
		ports, _, _ := unstructured.NestedSlice(svc.Object, "spec", "ports")
		matched, exposed := false, []string{}
		for _, raw := range ports {
			port := raw.(map[string]any)
			exposed = append(exposed, fmt.Sprintf("%v/%v", port["name"], port["port"]))
			if number, ok := b.port["number"]; ok && fmt.Sprint(number) == fmt.Sprint(port["port"]) {
				matched = true
			}
			if name, ok := b.port["name"]; ok && name == port["name"] {
				matched = true
			}
		}
		if !matched {
			p := fmt.Sprintf("Ingress backend port %v is not exposed by Service %q (ports name/port: %s)", portLabel(b.port), b.service, strings.Join(exposed, ", "))
			if !reported[p] {
				reported[p] = true
				problems = append(problems, p)
			}
			continue
		}
		if healthy, _, err := CheckService(ctx, r, svc); err == nil && !healthy && !reported[b.service] {
			reported[b.service] = true
			problems = append(problems, fmt.Sprintf("Ingress backend Service %q selects no Pod or workload template", b.service))
		}
	}
	return problems, nil
}

func portLabel(port map[string]any) string {
	if name, ok := port["name"]; ok {
		return fmt.Sprintf("%q", name)
	}
	return fmt.Sprint(port["number"])
}

// selectorProblems reports a label selector at path that matches no Pod and no
// workload template in the namespace; an empty selector selects everything.
func selectorProblems(ctx context.Context, r PodReader, u *unstructured.Unstructured, what string, path ...string) ([]string, error) {
	raw, ok, _ := unstructured.NestedMap(u.Object, path...)
	if !ok {
		return nil, nil
	}
	selector, err := toSelector(raw)
	if err != nil || selector.Empty() {
		return nil, err
	}
	matched, err := selectsAnything(ctx, r, u.GetNamespace(), selector)
	if err != nil || matched {
		return nil, err
	}
	return []string{fmt.Sprintf("%s %s matches no Pod or workload template in namespace %s", what, selector, u.GetNamespace())}, nil
}

func networkPolicyProblems(ctx context.Context, r PodReader, u *unstructured.Unstructured) ([]string, error) {
	problems, err := selectorProblems(ctx, r, u, "NetworkPolicy podSelector", "spec", "podSelector")
	if err != nil {
		return nil, err
	}
	// A same-namespace peer that matches nothing silently blocks the traffic
	// the rule was written to allow.
	for _, direction := range []struct{ rules, peers string }{{"ingress", "from"}, {"egress", "to"}} {
		rules, _, _ := unstructured.NestedSlice(u.Object, "spec", direction.rules)
		for n, rule := range rules {
			peers, _, _ := unstructured.NestedSlice(rule.(map[string]any), direction.peers)
			for m, peer := range peers {
				p := peer.(map[string]any)
				if _, crossNamespace := p["namespaceSelector"]; crossNamespace {
					continue
				}
				raw, ok := p["podSelector"].(map[string]any)
				if !ok {
					continue
				}
				selector, err := toSelector(raw)
				if err != nil || selector.Empty() {
					continue
				}
				matched, err := selectsAnything(ctx, r, u.GetNamespace(), selector)
				if err != nil {
					return nil, err
				}
				if !matched {
					problems = append(problems, fmt.Sprintf("NetworkPolicy %s[%d].%s[%d].podSelector %s matches no Pod or workload template, so that rule allows no traffic", direction.rules, n, direction.peers, m, selector))
				}
			}
		}
	}
	return problems, nil
}

// cronJobProblems reports a CronJob whose most recent Job failed with the
// current template. A failure that predates a template change is not held
// against the CronJob; its next run proves the repair or reopens the incident.
func cronJobProblems(ctx context.Context, r PodReader, u *unstructured.Unstructured) ([]string, error) {
	if suspended, _, _ := unstructured.NestedBool(u.Object, "spec", "suspend"); suspended {
		return nil, nil
	}
	jobs, err := r.List(ctx, "batch/v1", "Job", u.GetNamespace(), "")
	if err != nil {
		return nil, err
	}
	var latest *unstructured.Unstructured
	for _, job := range jobs {
		for _, owner := range job.GetOwnerReferences() {
			if owner.UID == u.GetUID() && owner.Controller != nil && *owner.Controller {
				if latest == nil {
					latest = job
				} else if before, created := latest.GetCreationTimestamp(), job.GetCreationTimestamp(); before.Before(&created) {
					latest = job
				}
			}
		}
	}
	if latest == nil || !jobFailed(latest) {
		return nil, nil
	}
	current, _, _ := unstructured.NestedMap(u.Object, "spec", "jobTemplate", "spec", "template", "spec")
	ran, _, _ := unstructured.NestedMap(latest.Object, "spec", "template", "spec")
	a, _ := api.Hash(current)
	b, _ := api.Hash(ran)
	if a != b {
		return nil, nil
	}
	reason, message := "", ""
	conditions, _, _ := unstructured.NestedSlice(latest.Object, "status", "conditions")
	for _, c := range conditions {
		m := c.(map[string]any)
		if (m["type"] == "Failed" || m["type"] == "FailureTarget") && m["status"] == "True" {
			reason, message = fmt.Sprint(m["reason"]), fmt.Sprint(m["message"])
		}
	}
	return []string{fmt.Sprintf("most recent Job %s failed (%s: %s) with the current job template", latest.GetName(), reason, message)}, nil
}

func jobFailed(job *unstructured.Unstructured) bool {
	conditions, _, _ := unstructured.NestedSlice(job.Object, "status", "conditions")
	for _, c := range conditions {
		m, _ := c.(map[string]any)
		if (m["type"] == "Failed" || m["type"] == "FailureTarget") && m["status"] == "True" {
			return true
		}
	}
	return false
}

// configMapProblems reports optional key references to u that are missing
// while an existing key differs by at most two characters: the consumer
// starts without the value, so the typo is otherwise silent. Missing required
// keys already fail the consuming Pod, which is investigated instead.
func configMapProblems(ctx context.Context, r PodReader, u *unstructured.Unstructured) ([]string, error) {
	keys := []string{}
	for _, field := range []string{"data", "binaryData"} {
		data, _, _ := unstructured.NestedMap(u.Object, field)
		for k := range data {
			keys = append(keys, k)
		}
	}
	has := map[string]bool{}
	for _, k := range keys {
		has[k] = true
	}
	problems := []string{}
	err := eachPodSpec(ctx, r, u.GetNamespace(), func(owner string, spec map[string]any) {
		for _, ref := range configMapKeyRefs(spec, u.GetName()) {
			if !ref.optional || has[ref.key] {
				continue
			}
			if near := nearestName(ref.key, keys); near != "" {
				problems = append(problems, fmt.Sprintf("%s references optional key %q of ConfigMap %s, which does not exist (nearest key: %q); it starts without that value", owner, ref.key, u.GetName(), near))
			}
		}
	})
	return problems, err
}

type keyRef struct {
	key      string
	optional bool
}

func configMapKeyRefs(spec map[string]any, name string) []keyRef {
	var refs []keyRef
	for _, group := range []string{"initContainers", "containers"} {
		containers, _, _ := unstructured.NestedSlice(spec, group)
		for _, c := range containers {
			env, _, _ := unstructured.NestedSlice(c.(map[string]any), "env")
			for _, e := range env {
				ref, ok, _ := unstructured.NestedMap(e.(map[string]any), "valueFrom", "configMapKeyRef")
				if ok && ref["name"] == name {
					optional, _ := ref["optional"].(bool)
					refs = append(refs, keyRef{fmt.Sprint(ref["key"]), optional})
				}
			}
		}
	}
	volumes, _, _ := unstructured.NestedSlice(spec, "volumes")
	for _, v := range volumes {
		cm, ok, _ := unstructured.NestedMap(v.(map[string]any), "configMap")
		if !ok || cm["name"] != name {
			continue
		}
		optional, _ := cm["optional"].(bool)
		items, _, _ := unstructured.NestedSlice(cm, "items")
		for _, item := range items {
			refs = append(refs, keyRef{fmt.Sprint(item.(map[string]any)["key"]), optional})
		}
	}
	return refs
}

var workloadKinds = []struct{ version, kind string }{{"apps/v1", "Deployment"}, {"apps/v1", "StatefulSet"}, {"apps/v1", "DaemonSet"}, {"batch/v1", "Job"}}

// eachPodSpec visits the Pod spec of every workload template, CronJob job
// template and unowned Pod in the namespace.
func eachPodSpec(ctx context.Context, r PodReader, namespace string, visit func(owner string, spec map[string]any)) error {
	for _, kind := range append(workloadKinds, struct{ version, kind string }{"batch/v1", "CronJob"}, struct{ version, kind string }{"v1", "Pod"}) {
		items, err := r.List(ctx, kind.version, kind.kind, namespace, "")
		if err != nil {
			return err
		}
		for _, w := range items {
			path := []string{"spec", "template", "spec"}
			switch kind.kind {
			case "CronJob":
				path = []string{"spec", "jobTemplate", "spec", "template", "spec"}
			case "Pod":
				if len(w.GetOwnerReferences()) > 0 {
					continue
				}
				path = []string{"spec"}
			}
			if spec, ok, _ := unstructured.NestedMap(w.Object, path...); ok {
				visit(kind.kind+"/"+w.GetName(), spec)
			}
		}
	}
	return nil
}

// selectsAnything reports whether selector matches a live Pod or the Pod
// template of a workload, so intentionally scaled-down workloads still count.
func selectsAnything(ctx context.Context, r PodReader, namespace string, selector labels.Selector) (bool, error) {
	pods, err := r.List(ctx, "v1", "Pod", namespace, selector.String())
	if err != nil {
		return false, err
	}
	for _, p := range pods {
		if p.GetDeletionTimestamp() == nil && selector.Matches(labels.Set(p.GetLabels())) {
			return true, nil
		}
	}
	for _, kind := range workloadKinds {
		items, err := r.List(ctx, kind.version, kind.kind, namespace, "")
		if err != nil {
			return false, err
		}
		for _, w := range items {
			template, _, _ := unstructured.NestedStringMap(w.Object, "spec", "template", "metadata", "labels")
			if selector.Matches(labels.Set(template)) {
				return true, nil
			}
		}
	}
	return false, nil
}

func toSelector(raw map[string]any) (labels.Selector, error) {
	var selector metav1.LabelSelector
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &selector); err != nil {
		return nil, err
	}
	return metav1.LabelSelectorAsSelector(&selector)
}

// nearestName returns the candidate within two edits of name, if exactly one
// is closest; a typo is then the likely cause.
func nearestName(name string, candidates []string) string {
	best, bestDistance, ties := "", 3, 0
	for _, c := range candidates {
		if c == name {
			continue
		}
		switch d := editDistance(name, c); {
		case d < bestDistance:
			best, bestDistance, ties = c, d, 0
		case d == bestDistance:
			ties++
		}
	}
	if ties > 0 {
		return ""
	}
	return best
}
