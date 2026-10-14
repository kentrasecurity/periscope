package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
)

// maxLogScans bounds the workloads whose logs one scan reads; successive
// scans rotate through larger scopes.
const maxLogScans = 20

// applicationErrors is the experimental pass for healthy workloads whose
// recent logs repeat an error with a common Kubernetes-side cause. It costs
// log reads, no model calls, and never runs unless the owner enabled it.
func (i *Investigator) applicationErrors(ctx context.Context, s api.Scope, unhealthy []Finding) ([]Finding, []string) {
	if !i.Policy.Experimental.ApplicationErrors {
		return nil, nil
	}
	logs, ok := i.Collector.Reader.(executor.RecentLogReader)
	if !ok {
		return nil, []string{"application errors: recent logs unavailable"}
	}
	known := map[string]bool{}
	for _, f := range unhealthy {
		known[f.Target.UID] = true
	}
	type candidate struct {
		ref api.TargetRef
	}
	var candidates []candidate
	gaps := []string{}
	for _, ns := range s.Namespaces {
		for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet"} {
			ref := api.TargetRef{APIVersion: "apps/v1", Kind: kind, Namespace: ns}
			if !i.Policy.ReadAllowed(ref) {
				continue
			}
			items, err := i.Collector.Reader.List(ctx, ref.APIVersion, kind, ns, "")
			if err != nil {
				gaps = append(gaps, fmt.Sprintf("%s/%s: application error scan unavailable", ns, kind))
				continue
			}
			for _, u := range items {
				ref.Name, ref.UID = u.GetName(), string(u.GetUID())
				if known[ref.UID] || u.GetDeletionTimestamp() != nil || api.IsOperatorInfrastructure(u.GetLabels()) || scaledToZero(u) || !s.Matches(ref, u) {
					continue
				}
				candidates = append(candidates, candidate{ref})
			}
		}
	}
	start := 0
	if len(candidates) > maxLogScans {
		start = int(time.Now().Unix()/60) * maxLogScans % len(candidates)
		gaps = append(gaps, fmt.Sprintf("application errors: %d of %d workloads scanned this pass", maxLogScans, len(candidates)))
	}
	findings := []Finding{}
	for n := 0; n < len(candidates) && n < maxLogScans; n++ {
		ref := candidates[(start+n)%len(candidates)].ref
		u, err := i.Collector.Reader.Get(ctx, ref)
		if err != nil {
			continue
		}
		match, err := executor.ScanLogSignatures(ctx, i.Collector.Reader, logs, u)
		if err != nil || match.Lines < executor.LogSignatureThreshold {
			continue
		}
		target := ref
		target.UID = ""
		check := api.Check{ID: "application-errors", Type: "LogSignature", Target: target, Query: match.Signature, TimeoutSeconds: 600, StableWindowSeconds: 60}
		fingerprint, _ := api.Hash([]any{ref, "log-signature", match.Signature})
		findings = append(findings, Finding{Target: ref, Checks: []api.Check{check}, FailureFingerprint: fingerprint})
	}
	return findings, gaps
}
