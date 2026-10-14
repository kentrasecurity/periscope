package kube

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type approvalReader interface {
	Approvals(context.Context, string) ([]*Approval, error)
}

func CurrentApprovals(ctx context.Context, b approvalReader, p *Plan) ([]*Approval, error) {
	if filtered, ok := b.(interface {
		ApprovalsForPlan(context.Context, string, string) ([]*Approval, error)
	}); ok {
		items, err := filtered.ApprovalsForPlan(ctx, p.Object.GetNamespace(), string(p.Object.GetUID()))
		if err != nil {
			return nil, err
		}
		// Exact status reference preserves approvals created before labels were introduced.
		if exact, ok := b.(interface {
			GetTask(context.Context, string, string) (*Task, error)
			GetApproval(context.Context, string, string) (*Approval, error)
		}); ok {
			t, e := exact.GetTask(ctx, p.Object.GetNamespace(), p.Spec.TaskRef.Name)
			if e == nil && t.Status.ApprovalRef != nil {
				a, e := exact.GetApproval(ctx, p.Object.GetNamespace(), t.Status.ApprovalRef.Name)
				if e == nil && string(a.Object.GetUID()) == t.Status.ApprovalRef.UID && a.Spec.PlanUID == string(p.Object.GetUID()) {
					seen := false
					for _, item := range items {
						if item.Object.GetUID() == a.Object.GetUID() {
							seen = true
						}
					}
					if !seen {
						items = append(items, a)
					}
				}
			}
		}
		return items, nil
	}
	items, err := b.Approvals(ctx, p.Object.GetNamespace())
	if err != nil {
		return nil, err
	}
	out := []*Approval{}
	for _, a := range items {
		if a.Spec.PlanUID == string(p.Object.GetUID()) {
			out = append(out, a)
		}
	}
	return out, nil
}

type planReader interface {
	ListPlans(context.Context, string) ([]*Plan, error)
}

func CurrentPlans(ctx context.Context, b planReader, ns string) ([]*Plan, error) {
	if current, ok := b.(interface {
		CurrentPlans(context.Context, string) ([]*Plan, error)
	}); ok {
		return current.CurrentPlans(ctx, ns)
	}
	return b.ListPlans(ctx, ns)
}
func (c *Client) ApprovalsForPlan(ctx context.Context, ns, uid string) ([]*Approval, error) {
	items, err := c.Dynamic.Resource(ApprovalGVR).Namespace(ns).List(ctx, metav1.ListOptions{LabelSelector: api.Group + "/plan-uid=" + uid, Limit: 128})
	if err != nil {
		return nil, err
	}
	if items.GetContinue() != "" {
		return nil, fmt.Errorf("current-plan approval limit exceeded")
	}
	out := []*Approval{}
	for n := range items.Items {
		u := items.Items[n].DeepCopy()
		a := &Approval{Object: u}
		if err = Decode(u.Object["spec"], &a.Spec); err != nil {
			return nil, err
		}
		if a.Spec.PlanUID == uid {
			out = append(out, a)
		}
	}
	return out, nil
}
func (c *Client) CurrentPlans(ctx context.Context, ns string) ([]*Plan, error) {
	out := []*Plan{}
	next := ""
	count := 0
	for {
		items, err := c.Dynamic.Resource(TaskGVR).Namespace(ns).List(ctx, metav1.ListOptions{Limit: 128, Continue: next})
		if err != nil {
			return nil, err
		}
		count += len(items.Items)
		if count > 1024 {
			return nil, fmt.Errorf("active task capacity exceeded")
		}
		for n := range items.Items {
			task, err := ParseTask(items.Items[n].DeepCopy())
			if err != nil {
				return nil, err
			}
			if task.Status.PlanRef == nil {
				continue
			}
			plan, err := c.GetPlan(ctx, ns, task.Status.PlanRef.Name)
			if err != nil {
				return nil, err
			}
			if string(plan.Object.GetUID()) == task.Status.PlanRef.UID {
				out = append(out, plan)
			}
		}
		next = items.GetContinue()
		if next == "" {
			return out, nil
		}
	}
}

func (c *Client) GetApproval(ctx context.Context, ns, name string) (*Approval, error) {
	u, err := c.Dynamic.Resource(ApprovalGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	a := &Approval{Object: u}
	if err = Decode(u.Object["spec"], &a.Spec); err != nil {
		return nil, err
	}
	return a, nil
}
