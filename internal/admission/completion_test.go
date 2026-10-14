package admission

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"
)

func TestCompletedJournalAcceptsFinalStateForOneAndTwoActions(t *testing.T) {
	for _, count := range []int{1, 2} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			v, b, r := requestSetup(t)
			p := b.Plans["demo/plan"]
			u, _ := b.Get(context.Background(), p.Spec.TargetRef)
			if count == 2 {
				u.Object["data"].(map[string]any)["other"] = "broken"
				v.Policy.Capabilities[0].Paths["/data/other"] = policy.ValueRule{Values: []any{"healthy"}}
				p.Spec.Actions = append(p.Spec.Actions, api.Action{ID: "repair-other", Type: "PatchResource", Target: p.Spec.TargetRef, Patch: []api.PatchOp{{Op: "replace", Path: "/data/other", Value: "healthy"}}})
			}
			p.Spec.Preconditions.SpecDigest, _ = api.DigestTarget(u)
			p.Spec.PolicyDigest = policy.PolicyDigest(v.Policy)
			p.Spec.Digest, _ = api.DigestPlan(p.Spec)
			b.ApprovalItems["demo/approve"].Spec.PlanDigest = p.Spec.Digest
			p.Status.Entries = nil
			for _, a := range p.Spec.Actions {
				before, _ := api.DigestTarget(u)
				u, _ = executor.PrepareResult(p, a, u)
				after, _ := executor.ResultDigest(u, a)
				p.Status.Entries = append(p.Status.Entries, api.JournalEntry{ID: a.ID, State: "Applied", Operation: executor.Operation(p, a.ID), BeforeDigest: before, AfterDigest: after, ResultUID: string(u.GetUID()), UpdatedAt: time.Now().UTC()})
			}
			b.PutResource(u)
			since := time.Now().UTC().Add(-130 * time.Second)
			p.Status.Phase = "Verifying"
			p.Status.StableSince = &since
			old := p.Object.DeepCopy()
			old.Object["spec"] = kube.JSONMap(p.Spec)
			old.Object["status"] = kube.JSONMap(p.Status)
			next := old.DeepCopy()
			done := p.Status
			done.Entries = append([]api.JournalEntry{}, p.Status.Entries...)
			done.Phase = "Succeeded"
			for n := range done.Entries {
				done.Entries[n].State = "Verified"
			}
			next.Object["status"] = kube.JSONMap(done)
			r.Request.Name = "plan"
			r.Request.Kind = metav1.GroupVersionKind{Group: api.Group, Version: api.Version, Kind: "ActionPlan"}
			r.Request.Resource = metav1.GroupVersionResource{Group: api.Group, Version: api.Version, Resource: "actionplans"}
			r.Request.SubResource = "status"
			r.Request.Object.Raw, _ = json.Marshal(next.Object)
			r.Request.OldObject.Raw, _ = json.Marshal(old.Object)
			if response := v.Validate(context.Background(), r); !response.Allowed {
				t.Fatalf("valid completed journal denied: %v", response.Result)
			}
		})
	}
}
