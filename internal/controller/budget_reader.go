package controller

import (
	"context"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type budgetReader struct {
	evidence.Reader
	t    *kube.Task
	save func(context.Context, *kube.Task) error
}

func (b budgetReader) reserve(ctx context.Context) error {
	if err := reserveTask(b.t, 0, 1); err != nil {
		return err
	}
	b.t.Status.ToolCalls++
	return b.save(ctx, b.t)
}
func (b budgetReader) Get(ctx context.Context, t api.TargetRef) (*unstructured.Unstructured, error) {
	if err := b.reserve(ctx); err != nil {
		return nil, err
	}
	return b.Reader.Get(ctx, t)
}
func (b budgetReader) List(ctx context.Context, v, k, n, s string) ([]*unstructured.Unstructured, error) {
	if err := b.reserve(ctx); err != nil {
		return nil, err
	}
	return b.Reader.List(ctx, v, k, n, s)
}
func (b budgetReader) Logs(ctx context.Context, n, p, c string, previous bool, limit int64) (string, error) {
	if err := b.reserve(ctx); err != nil {
		return "", err
	}
	return b.Reader.Logs(ctx, n, p, c, previous, limit)
}
func (b budgetReader) DescribeAPI(ctx context.Context, t api.TargetRef) (string, error) {
	if err := b.reserve(ctx); err != nil {
		return "", err
	}
	return b.Reader.DescribeAPI(ctx, t)
}
