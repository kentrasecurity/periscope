package kube

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	coord "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"time"
)

func ClaimName(target string) string { h, _ := api.Hash(target); return "periscope-" + h[7:39] }
func (c *Client) Claim(ctx context.Context, namespace, target, holder string) (bool, error) {
	return c.claim(ctx, namespace, target, holder, nil)
}
func (c *Client) ClaimPlan(ctx context.Context, namespace, target string, p *Plan) (bool, error) {
	return c.claim(ctx, namespace, target, string(p.Object.GetUID()), map[string]string{api.Group + "/plan": p.Object.GetName(), api.Group + "/plan-namespace": p.Object.GetNamespace()})
}
func (c *Client) claim(ctx context.Context, namespace, target, holder string, annotations map[string]string) (bool, error) {
	name := ClaimName(target)
	leases := c.Coord.Leases(namespace)
	lease, e := leases.Get(ctx, name, metav1.GetOptions{})
	now := metav1.NewMicroTime(time.Now().UTC())
	duration := int32(120)
	if apierrors.IsNotFound(e) {
		_, e = leases.Create(ctx, &coord.Lease{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Annotations: annotations}, Spec: coord.LeaseSpec{HolderIdentity: &holder, AcquireTime: &now, RenewTime: &now, LeaseDurationSeconds: &duration}}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(e) {
			return false, nil
		}
		return e == nil, e
	}
	if e != nil {
		return false, e
	}
	if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != "" && *lease.Spec.HolderIdentity != holder {
		if lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil {
			return false, nil
		}
		if lease.Spec.RenewTime.Add(time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second).After(now.Time) {
			return false, nil
		}
	}
	if annotations != nil {
		lease.Annotations = annotations
	}
	lease.Spec.HolderIdentity = &holder
	lease.Spec.RenewTime = &now
	lease.Spec.LeaseDurationSeconds = &duration
	_, e = leases.Update(ctx, lease, metav1.UpdateOptions{})
	if apierrors.IsConflict(e) {
		return false, nil
	}
	return e == nil, e
}
func (c *Client) Release(ctx context.Context, namespace, target, holder string) error {
	leases := c.Coord.Leases(namespace)
	lease, e := leases.Get(ctx, ClaimName(target), metav1.GetOptions{})
	if apierrors.IsNotFound(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != holder {
		return nil
	}
	empty := ""
	lease.Spec.HolderIdentity = &empty
	_, e = leases.Update(ctx, lease, metav1.UpdateOptions{})
	return e
}

func (c *Client) HasClaim(ctx context.Context, namespace, target, holder string) (bool, error) {
	lease, e := c.Coord.Leases(namespace).Get(ctx, ClaimName(target), metav1.GetOptions{})
	if apierrors.IsNotFound(e) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != holder || lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil {
		return false, nil
	}
	return lease.Spec.RenewTime.Add(time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second).After(time.Now().UTC()), nil
}
