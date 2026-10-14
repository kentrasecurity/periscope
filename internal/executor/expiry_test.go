package executor

import (
	"context"
	"testing"
	"time"
)

func TestConsumedApprovalExpiryIsReported(t *testing.T) {
	e, b, p, now := execution(t)
	if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(20 * time.Minute)
	if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
		t.Fatal(err)
	}
	if p.Status.Phase != "Failed" || b.Tasks["demo/fix"].Status.Phase != "Failed" {
		t.Fatal("expired consumed approval silently left execution running")
	}
}
