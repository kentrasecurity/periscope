package controller

import (
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"time"
)

const maxSuspects = 100

// suspectKey identifies a resource instance; absent targets have no UID.
func suspectKey(t api.TargetRef) string { return api.ResourceKey(t) + "#" + t.UID }

// debounce holds back findings until they have stayed unhealthy for the task's
// grace period. Rollouts, image pulls and starting Pods are briefly unhealthy;
// treating them as incidents would spend inference and could start repairs of
// workloads that heal on their own. Known incidents are rechecks and pass
// immediately.
//
// Up to maxSuspects failing resources, including incidents and those past the
// grace period, keep their first-seen time, so a persistent failure stays
// ready (for example after its incident is archived). A suspect is forgotten
// when the scan listed its kind and did not find it; bounded passes and
// unreadable kinds do not observe every resource, and absence from a kind
// that was not listed is not recovery.
func debounce(t *kube.Task, findings []Finding, covered coverage, now time.Time) (ready []Finding, waiting int) {
	grace := t.Spec.GracePeriod()
	known := map[string]bool{}
	if t.Status.Incident != nil {
		known[suspectKey(t.Status.Incident.Target)] = true
	}
	for _, incident := range t.Status.PendingIncidents {
		known[suspectKey(incident.Target)] = true
	}
	previous := map[string]time.Time{}
	for _, s := range t.Status.Suspects {
		previous[suspectKey(s.Target)] = s.Since
	}
	suspects := []api.Suspect{}
	found := map[string]bool{}
	for _, f := range findings {
		key := suspectKey(f.Target)
		found[key] = true
		since, seen := previous[key]
		if !seen {
			since = now
		}
		if len(suspects) < maxSuspects {
			suspects = append(suspects, api.Suspect{Target: f.Target, Since: since})
		} else if !known[key] {
			ready = append(ready, f) // untracked: report rather than wait forever
			continue
		}
		if known[key] || grace <= 0 || now.Sub(since) >= grace {
			ready = append(ready, f)
			continue
		}
		waiting++
	}
	for _, s := range t.Status.Suspects {
		if !found[suspectKey(s.Target)] && !covered.covers(s.Target) && len(suspects) < maxSuspects {
			suspects = append(suspects, s)
		}
	}
	t.Status.Suspects = suspects
	return ready, waiting
}

func graceReport(t *kube.Task, waiting int) string {
	return fmt.Sprintf("%d resource(s) unhealthy for less than the %s grace period (see suspects); an incident opens if they stay unhealthy.", waiting, t.Spec.GracePeriod())
}

// inGracePeriod records a single-target task's failure as a suspect and
// reports whether it is still inside the grace period.
func inGracePeriod(t *kube.Task, target api.TargetRef, now time.Time) bool {
	_, waiting := debounce(t, []Finding{{Target: target}}, coverage{all: true}, now)
	return waiting > 0
}
