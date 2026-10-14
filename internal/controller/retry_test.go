package controller

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"testing"
	"time"
)

func TestFailedRepairReinvestigatesRemainingFailure(t *testing.T) {
	i, b, m := setup(t)
	i.Policy.Authorization = "RBAC"
	i.Collector.Policy = i.Policy
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	task := b.Tasks["demo/fix"]
	p := b.Plans["demo/"+task.Status.PlanRef.Name]
	p.Status.Phase = "Failed"
	p.Status.Conditions = []api.Condition{{Reason: "VerificationTimedOut", LastTransitionTime: time.Now().Add(-time.Minute)}}
	task.Status.Phase = "Failed"
	if err := i.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if m.calls != 2 || len(b.Plans) != 2 {
		t.Fatalf("remaining failure was not reinvestigated: calls=%d plans=%d", m.calls, len(b.Plans))
	}
	if task.Status.Phase != "AwaitingApproval" {
		t.Fatal("fresh human decision not requested")
	}
}
