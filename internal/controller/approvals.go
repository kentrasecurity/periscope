package controller

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"time"
)

type approvalCreator interface {
	CreateApproval(context.Context, string, string, api.ApprovalSpec) (*kube.Approval, error)
}

func (i *Investigator) requestApproval(ctx context.Context, t *kube.Task, p *kube.Plan) error {
	if !i.Policy.RBAC() || (t.Spec.Mode != "HumanApproved" && t.Spec.Mode != "Automatic") {
		return nil
	}
	writer, ok := i.Backend.(approvalCreator)
	if !ok {
		return nil
	}
	name := p.Object.GetName() + "-review"
	if reader, ok := i.Backend.(interface {
		Approvals(context.Context, string) ([]*kube.Approval, error)
	}); ok {
		items, err := kube.CurrentApprovals(ctx, reader, p)
		if err != nil {
			return err
		}
		expired := false
		for _, a := range items {
			if a.Spec.PlanUID != string(p.Object.GetUID()) || a.Spec.PlanDigest != p.Spec.Digest {
				continue
			}
			if a.Spec.Decision == "Reject" {
				t.Status.Phase = "Rejected"
				t.Status.Report = "Human rejected this proposal; monitoring continues without executing it."
				return i.Backend.SaveTaskStatus(ctx, t)
			}
			if a.Spec.ExpiresAt.After(time.Now()) && !a.Spec.ExpiresAt.After(a.Object.GetCreationTimestamp().Time.Add(30*time.Minute)) {
				t.Status.ApprovalRef = &api.ObjectRef{Name: a.Object.GetName(), UID: string(a.Object.GetUID())}
				return i.Backend.SaveTaskStatus(ctx, t)
			}
			expired = true
		}
		if expired {
			name = fmt.Sprintf("%s-review-%d", p.Object.GetName(), time.Now().Unix()/1800)
		}
	}
	decision := "Pending"
	if t.Spec.Mode == "Automatic" {
		decision = "Approve"
	}
	created, err := writer.CreateApproval(ctx, t.Object.GetNamespace(), name, api.ApprovalSpec{PlanName: p.Object.GetName(), Decision: decision, TaskUID: string(t.Object.GetUID()), PlanUID: string(p.Object.GetUID()), PlanDigest: p.Spec.Digest, ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(29 * time.Minute)})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	if err == nil {
		t.Status.ApprovalRef = &api.ObjectRef{Name: created.Object.GetName(), UID: string(created.Object.GetUID())}
		return i.Backend.SaveTaskStatus(ctx, t)
	}
	return err
}
