package kube

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *Client) Authorize(ctx context.Context, a api.Action) error {
	if c.Authz == nil {
		return fmt.Errorf("executor authorization client unavailable")
	}
	m, err := c.Mapping(a.Target)
	if err != nil {
		return err
	}
	verb := "patch"
	switch a.Type {
	case "CreateResource":
		verb = "create"
	case "DeleteResource":
		verb = "delete"
	}
	result, err := c.Authz.SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Namespace: a.Target.Namespace, Group: m.Resource.Group, Version: m.Resource.Version, Resource: m.Resource.Resource, Name: a.Target.Name, Verb: verb}}}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("authorization check unavailable: %w", err)
	}
	if !result.Status.Allowed {
		return fmt.Errorf("Kubernetes RBAC denies %s on %s/%s", verb, m.Resource.Resource, a.Target.Name)
	}
	return nil
}
