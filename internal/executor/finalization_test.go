package executor

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"testing"
)

func TestTerminalPlanFinishesInterruptedTaskAndReleasesClaim(t *testing.T) {
	for _, phase := range []string{"Succeeded", "Failed"} {
		t.Run(phase, func(t *testing.T) {
			e, b, p, _ := execution(t)
			p.Status.Phase = phase
			b.Tasks["demo/fix"].Status.Phase = "Verifying"
			b.Claims[api.ClaimKey(p.Spec.TargetRef)] = string(p.Object.GetUID())
			if err := e.Reconcile(context.Background(), "demo", "fix"); err != nil {
				t.Fatal(err)
			}
			if b.Tasks["demo/fix"].Status.Phase != phase || b.Claims[api.ClaimKey(p.Spec.TargetRef)] != "" || b.Mutations != 0 {
				t.Fatal("terminal plan did not finish task and release claim without mutation")
			}
		})
	}
}
