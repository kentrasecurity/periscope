package executor

import (
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"github.com/kentrasecurity/periscope/internal/policy"
	"testing"
)

func TestDecisionRequiredForNewApproval(t *testing.T) {
	task, plan, approval, target, c, now := approved(t)
	for _, decision := range []string{"Pending", "Reject"} {
		approval.Spec.Decision = decision
		if ValidateApproval(task, plan, approval, target, c, now) == nil {
			t.Fatalf("%s executed", decision)
		}
	}
	approval.Spec.Decision = "Approve"
	if err := ValidateApproval(task, plan, approval, target, c, now); err != nil {
		t.Fatal(err)
	}
}
func TestAutomaticDecisionBoundToExplicitTaskMode(t *testing.T) {
	task, plan, approval, target, c, now := approved(t)
	task.Spec.Mode = "Automatic"
	c.Authorization = "RBAC"
	c.Namespaces = []string{"demo"}
	plan.Spec.PolicyDigest = policy.PolicyDigest(c)
	plan.Spec.Digest, _ = api.DigestPlan(plan.Spec)
	approval.Spec.PlanDigest = plan.Spec.Digest
	approval.Spec.Decision = "Approve"
	if err := ValidateApproval(task, plan, approval, target, c, now); err != nil {
		t.Fatal(err)
	}
	_ = api.Version
}

func TestApprovalCannotCrossMonitoringCycles(t *testing.T) {
	task, plan, approval, target, c, now := approved(t)
	task.Status.Cycle = 2
	spec := kube.JSONMap(plan.Spec)
	spec["taskCycle"] = int64(1)
	_ = kube.Decode(spec, &plan.Spec)
	plan.Spec.Digest, _ = api.DigestPlan(plan.Spec)
	approval.Spec.PlanDigest = plan.Spec.Digest
	if ValidateApproval(task, plan, approval, target, c, now) == nil {
		t.Fatal("old cycle approval replayed through restored plan pointer")
	}
}
func TestIncidentChecksCannotBeWeakened(t *testing.T) {
	task, p, a, u, c, now := approved(t)
	c.Authorization = "RBAC"
	c.Namespaces = []string{"demo"}
	p.Spec.PolicyDigest = policy.PolicyDigest(c)
	checks := []api.Check{api.VerificationCheck(p.Spec.TargetRef, p.Spec.Verification)}
	digest, _ := api.Hash(checks)
	task.Status.Incident = &api.IncidentStatus{ID: "incident", OriginalChecks: checks, OriginalChecksDigest: digest}
	p.Spec.IncidentID = "incident"
	p.Spec.OriginalChecksDigest = digest
	p.Spec.Verification.Expected = "broken"
	p.Spec.Actions[0].Patch[0].Value = "broken"
	p.Spec.Digest, _ = api.DigestPlan(p.Spec)
	a.Spec.PlanDigest = p.Spec.Digest
	if ValidateApproval(task, p, a, u, c, now) == nil {
		t.Fatal("weakened original goal accepted")
	}
}
