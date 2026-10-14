package admission

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"
)

func TestExecutorCannotRewriteJournalAuthorization(t *testing.T) {
	v, b, r := requestSetup(t)
	p := b.Plans["demo/plan"]
	old := p.Object.DeepCopy()
	old.Object["spec"] = kube.JSONMap(p.Spec)
	old.Object["status"] = kube.JSONMap(p.Status)
	next := old.DeepCopy()
	bad := p.Status
	bad.Entries = append([]api.JournalEntry{}, p.Status.Entries...)
	bad.Entries[0].BeforeDigest = "forged-baseline"
	next.Object["status"] = kube.JSONMap(bad)
	r.Request.Name = "plan"
	r.Request.Kind = metav1.GroupVersionKind{Group: api.Group, Version: api.Version, Kind: "ActionPlan"}
	r.Request.Resource = metav1.GroupVersionResource{Group: api.Group, Version: api.Version, Resource: "actionplans"}
	r.Request.SubResource = "status"
	r.Request.Object.Raw, _ = json.Marshal(next.Object)
	r.Request.OldObject.Raw, _ = json.Marshal(old.Object)
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("executor could rewrite authorization journal")
	}
}

func TestStableWindowCannotStartBeforeActionApplied(t *testing.T) {
	v, b, r := requestSetup(t)
	p := b.Plans["demo/plan"]
	old := p.Object.DeepCopy()
	old.Object["spec"] = kube.JSONMap(p.Spec)
	old.Object["status"] = kube.JSONMap(p.Status)
	next := old.DeepCopy()
	bad := p.Status
	now := time.Now().UTC()
	bad.StableSince = &now
	bad.Phase = "Verifying"
	next.Object["status"] = kube.JSONMap(bad)
	r.Request.Name = "plan"
	r.Request.Kind = metav1.GroupVersionKind{Group: api.Group, Version: api.Version, Kind: "ActionPlan"}
	r.Request.Resource = metav1.GroupVersionResource{Group: api.Group, Version: api.Version, Resource: "actionplans"}
	r.Request.SubResource = "status"
	r.Request.Object.Raw, _ = json.Marshal(next.Object)
	r.Request.OldObject.Raw, _ = json.Marshal(old.Object)
	if v.Validate(context.Background(), r).Allowed {
		t.Fatal("verification window started before an action was applied")
	}
}
