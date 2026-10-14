package controller

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sort"
	"strings"
)

type Finding struct {
	Target             api.TargetRef
	Owner              *api.TargetRef
	Checks             []api.Check
	FailureFingerprint string
}

func (i *Investigator) DiscoverIncidents(ctx context.Context, s api.Scope) ([]Finding, []string, error) {
	findings, gaps, _, err := i.discoverIncidents(ctx, s, nil)
	return findings, gaps, err
}

// coverage records what a scan observed. A suspect whose kind was listed in
// its namespace but not found has recovered; one whose kind was not listed
// (bounded pass, unreadable kind) keeps waiting.
type coverage struct {
	all   bool
	kinds map[string]bool
}

func kindKey(namespace, apiVersion, kind string) string {
	return namespace + "/" + apiVersion + "/" + kind
}

func (c coverage) covers(t api.TargetRef) bool {
	return c.all || c.kinds[kindKey(t.Namespace, t.APIVersion, t.Kind)]
}

// discoverIncidents also reports which kinds the pass listed; bounded passes
// resume at the cursor next time.
func (i *Investigator) discoverIncidents(ctx context.Context, s api.Scope, cursor *int) ([]Finding, []string, coverage, error) {
	covered := coverage{kinds: map[string]bool{}}
	if err := s.Validate(); err != nil {
		return nil, nil, covered, err
	}
	fallback := []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}, {APIVersion: "apps/v1", Kind: "Deployment"}, {APIVersion: "apps/v1", Kind: "StatefulSet"}, {APIVersion: "apps/v1", Kind: "DaemonSet"}, {APIVersion: "batch/v1", Kind: "Job"}}
	resources := s.Resources
	gaps := []string{}
	needsDiscovery := len(resources) == 0
	for _, r := range resources {
		if r.APIVersion == "" {
			needsDiscovery = true
		}
	}
	if needsDiscovery {
		available := fallback
		if source, ok := i.Collector.Reader.(interface {
			NamespacedResources(context.Context) ([]api.ResourceSelector, error)
		}); ok {
			all, err := source.NamespacedResources(ctx)
			if err != nil {
				gaps = append(gaps, "API discovery incomplete; built-in health coverage only")
			} else {
				available = all
			}
		}
		if len(resources) == 0 {
			resources = available
		} else {
			expanded := []api.ResourceSelector{}
			for _, r := range resources {
				if r.APIVersion != "" {
					expanded = append(expanded, r)
					continue
				}
				for _, kind := range available {
					kind.Name = r.Name
					kind.LabelSelector = r.LabelSelector
					expanded = append(expanded, kind)
				}
			}
			resources = expanded
		}
	}
	if len(resources) == 0 {
		return nil, append(gaps, "no discoverable health resources"), covered, nil
	}
	findings := []Finding{}
	seen := map[string]bool{}
	reported := map[string]bool{}
	calls := 0
	total := len(s.Namespaces) * len(resources)
	start, visited := 0, 0
	if cursor != nil {
		start = *cursor % total
		defer func() { *cursor = (start + visited) % total }()
	}
	for step := 0; step < total; step++ {
		job := (start + step) % total
		ns := s.Namespaces[job/len(resources)]
		resource := resources[job%len(resources)]
		visited = step
		if len(findings) >= 100 {
			return findings, append(gaps, "incident discovery limit exhausted"), covered, nil
		}
		if calls >= 100 {
			return findings, append(gaps, "discovery call budget exhausted"), covered, nil
		}
		visited = step + 1
		if strings.HasPrefix(resource.APIVersion, api.Group+"/") || executor.NoHealthSemantics(resource.Kind) {
			continue
		}
		ref := api.TargetRef{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: ns}
		if !i.Policy.ReadAllowed(ref) {
			gaps = append(gaps, "namespace not enrolled: "+ns)
			continue
		}
		calls++
		objects, err := i.Collector.Reader.List(ctx, ref.APIVersion, ref.Kind, ns, resource.LabelSelector)
		if err != nil {
			gaps = append(gaps, fmt.Sprintf("%s/%s: read unavailable", ns, resource.Kind))
			continue
		}
		covered.kinds[kindKey(ns, resource.APIVersion, resource.Kind)] = true
		if len(objects) > maxDiscoveredPerKind {
			objects = objects[:maxDiscoveredPerKind]
			gaps = append(gaps, fmt.Sprintf("%s/%s: listing truncated at %d", ns, resource.Kind, maxDiscoveredPerKind))
		}
		for _, u := range objects {
			if u.GetDeletionTimestamp() != nil || u.GetKind() == "Job" && jobCompleted(u) || completedJobPod(u) || api.IsOperatorInfrastructure(u.GetLabels()) || scaledToZero(u) {
				continue
			}
			ref.Name = u.GetName()
			ref.UID = string(u.GetUID())
			if !s.Matches(ref, u) {
				continue
			}
			v := api.Verification{Type: "ResourceHealthy", TimeoutSeconds: 180, StableWindowSeconds: 10}
			if u.GetKind() == "Pod" {
				v.Type = "PodRecovery"
			}
			if u.GetKind() == "Deployment" {
				v.Type = "DeploymentRecovery"
				v.HealthURL = i.Policy.HealthURL(ref)
			}
			healthy, _, checkErr := executor.CheckResource(u, v)
			if checkErr == nil && healthy && executor.ReferenceKinds(u.GetKind()) {
				healthy, _, _, checkErr = executor.CheckReferences(ctx, i.Collector.Reader, u)
			}
			if checkErr != nil {
				gap := fmt.Sprintf("%s/%s: explicit goal checks required for unknown health semantics", ns, resource.Kind)
				if executor.ReferenceKinds(u.GetKind()) {
					gap = fmt.Sprintf("%s/%s: reference observation unavailable", ns, resource.Kind)
				}
				if !reported[gap] && len(gaps) < 32 {
					reported[gap] = true
					gaps = append(gaps, gap)
				}
				continue
			}
			if healthy {
				continue
			}
			resolved := ref
			owner := (*api.TargetRef)(nil)
			failureObject := u
			for depth := 0; depth < 4; depth++ {
				var parentRef *api.TargetRef
				for _, o := range u.GetOwnerReferences() {
					if o.Controller != nil && *o.Controller {
						r := api.TargetRef{APIVersion: o.APIVersion, Kind: o.Kind, Namespace: ns, Name: o.Name, UID: string(o.UID)}
						parentRef = &r
						break
					}
				}
				if parentRef == nil {
					break
				}
				if !i.Policy.ReadAllowed(*parentRef) {
					break
				}
				p, err := i.Collector.Reader.Get(ctx, *parentRef)
				if err != nil || string(p.GetUID()) != parentRef.UID {
					break
				}
				u = p
				owner = parentRef
				if s.Matches(*parentRef, p) && (p.GetKind() == "Deployment" || p.GetKind() == "StatefulSet" || p.GetKind() == "DaemonSet") {
					resolved = *parentRef
					failureObject = p
					break
				}
				// A Job's template is immutable; failures of scheduled Jobs belong
				// to their CronJob's job template.
				if s.Matches(*parentRef, p) && (p.GetKind() == "Job" || p.GetKind() == "CronJob") {
					resolved = *parentRef
					failureObject = p
				}
			}
			if resolved.Kind == "CronJob" {
				// Failed Jobs and Pods outlive later successful runs; the CronJob's
				// own check decides whether its current template is failing.
				if ok, _, _, err := executor.CheckReferences(ctx, i.Collector.Reader, failureObject); err != nil || ok {
					continue
				}
			}
			if seen[resolved.UID] {
				continue
			}
			seen[resolved.UID] = true
			if resolved.Kind == "Deployment" {
				v.Type = "DeploymentRecovery"
				v.HealthURL = i.Policy.HealthURL(resolved)
			} else if resolved.Kind != "Pod" {
				v.Type = "ResourceHealthy"
			}
			fingerprint, _ := api.Hash([]any{resolved, executor.FailureSignature(failureObject)})
			findings = append(findings, Finding{Target: resolved, Owner: owner, Checks: []api.Check{api.VerificationCheck(resolved, v)}, FailureFingerprint: fingerprint})
		}
	}
	sort.Slice(findings, func(a, b int) bool {
		return findings[a].Target.Namespace+"/"+findings[a].Target.Name < findings[b].Target.Namespace+"/"+findings[b].Target.Name
	})
	return findings, gaps, covered, nil
}

const maxDiscoveredPerKind = 500

// scaledToZero reports workloads intentionally scaled down; zero replicas
// cannot fail, and an empty Deployment cannot prove recovery either.
func scaledToZero(u *unstructured.Unstructured) bool {
	switch u.GetKind() {
	case "Deployment", "StatefulSet", "ReplicaSet":
		replicas, found, _ := unstructured.NestedInt64(u.Object, "spec", "replicas")
		return found && replicas == 0
	}
	return false
}

func jobCompleted(u *unstructured.Unstructured) bool {
	success, _, _ := unstructured.NestedInt64(u.Object, "status", "succeeded")
	wanted, exists, _ := unstructured.NestedInt64(u.Object, "spec", "completions")
	if !exists {
		wanted = 1
	}
	if success >= wanted && wanted > 0 {
		return true
	}
	conditions, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	for _, c := range conditions {
		m, _ := c.(map[string]any)
		if m["type"] == "Complete" && m["status"] == "True" {
			return true
		}
	}
	return false
}

func completedJobPod(u *unstructured.Unstructured) bool {
	if u.GetKind() != "Pod" {
		return false
	}
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	if phase != "Succeeded" {
		return false
	}
	for _, owner := range u.GetOwnerReferences() {
		if owner.APIVersion == "batch/v1" && owner.Kind == "Job" && owner.Controller != nil && *owner.Controller {
			return true
		}
	}
	return false
}
