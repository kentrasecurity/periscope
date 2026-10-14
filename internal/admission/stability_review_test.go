package admission

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"
)

func TestChangedFingerprintCannotRetainElapsedStableWindow(t *testing.T) {
	v, b, r := requestSetup(t)
	p := b.Plans["demo/plan"]
	p.Spec.Checks = []api.Check{api.VerificationCheck(p.Spec.TargetRef, p.Spec.Verification)}
	p.Spec.Digest, _ = api.DigestPlan(p.Spec)
	b.ApprovalItems["demo/approve"].Spec.PlanDigest = p.Spec.Digest
	current, _ := executor.PrepareResult(p, p.Spec.Actions[0], b.Resources["demo/settings"])
	b.PutResource(current)
	p.Status.Entries[0].State = "Applied"
	p.Status.Entries[0].ResultUID = string(current.GetUID())
	p.Status.Phase = "Verifying"
	stamp := time.Now().UTC().Add(-180 * time.Second)
	p.Status.StableSince = &stamp
	p.Status.VerificationFingerprint = "previous-runtime"
	old := p.Object.DeepCopy()
	old.Object["spec"] = kube.JSONMap(p.Spec)
	old.Object["status"] = kube.JSONMap(p.Status)
	results, _ := (executor.CheckEvaluator{Reader: b, Pods: b}).EvaluateChecks(context.Background(), p.Spec.Checks)
	next := old.DeepCopy()
	status := p.Status
	status.Entries = append([]api.JournalEntry{}, p.Status.Entries...)
	status.Entries[0].State = "Verified"
	status.Phase = "Succeeded"
	status.VerificationFingerprint = executor.ChecksFingerprint(results)
	status.CheckResults = results
	next.Object["status"] = kube.JSONMap(status)
	r.Request.Name = "plan"
	r.Request.Kind = metav1.GroupVersionKind{Group: api.Group, Version: api.Version, Kind: "ActionPlan"}
	r.Request.Resource = metav1.GroupVersionResource{Group: api.Group, Version: api.Version, Resource: "actionplans"}
	r.Request.SubResource = "status"
	r.Request.Object.Raw, _ = json.Marshal(next.Object)
	r.Request.OldObject.Raw, _ = json.Marshal(old.Object)
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("changed fingerprint reused elapsed stable window")
	}
}
