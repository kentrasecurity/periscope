package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sort"
	"strings"
)

func (c *Client) Execute(ctx context.Context, a api.Action, before, desired *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	m, e := c.Mapping(a.Target)
	if e != nil {
		return nil, e
	}
	resource := c.Dynamic.Resource(m.Resource).Namespace(a.Target.Namespace)
	var dryRun []string
	if dry {
		dryRun = []string{metav1.DryRunAll}
	}
	switch a.Type {
	case "CreateResource":
		if before != nil || desired == nil {
			return nil, fmt.Errorf("invalid create state")
		}
		return resource.Create(ctx, desired, metav1.CreateOptions{DryRun: dryRun, FieldValidation: "Strict"})
	case "DeleteResource":
		if before == nil || a.Target.UID == "" || string(before.GetUID()) != a.Target.UID {
			return nil, fmt.Errorf("invalid delete identity")
		}
		uid := before.GetUID()
		version := before.GetResourceVersion()
		e = resource.Delete(ctx, a.Target.Name, metav1.DeleteOptions{DryRun: dryRun, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &version}})
		return nil, e
	case "PatchResource", "RestartWorkload":
		if before == nil || desired == nil || before.GetResourceVersion() == "" || before.GetUID() == "" {
			return nil, fmt.Errorf("conditional patch requires target version and UID")
		}
		ops := []api.PatchOp{{Op: "test", Path: "/metadata/resourceVersion", Value: before.GetResourceVersion()}, {Op: "test", Path: "/metadata/uid", Value: string(before.GetUID())}}
		keys := []string{}
		seen := map[string]bool{}
		for key := range before.Object {
			seen[key] = true
		}
		for key := range desired.Object {
			seen[key] = true
		}
		for key := range seen {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if key == "metadata" || key == "status" || key == "kind" || key == "apiVersion" {
				continue
			}
			left, _ := api.Hash(before.Object[key])
			right, _ := api.Hash(desired.Object[key])
			if left == right {
				continue
			}
			op := "replace"
			if _, ok := desired.Object[key]; !ok {
				op = "remove"
			}
			if _, ok := before.Object[key]; !ok {
				op = "add"
			}
			path := "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
			ops = append(ops, api.PatchOp{Op: op, Path: path, Value: desired.Object[key]})
		}
		beforeAnnotations := before.GetAnnotations()
		afterAnnotations := desired.GetAnnotations()
		left, _ := api.Hash(beforeAnnotations)
		right, _ := api.Hash(afterAnnotations)
		if left != right {
			ops = append(ops, api.PatchOp{Op: "add", Path: "/metadata/annotations", Value: afterAnnotations})
		}
		if l, _ := api.Hash(before.GetLabels()); true {
			r, _ := api.Hash(desired.GetLabels())
			if l != r {
				ops = append(ops, api.PatchOp{Op: "add", Path: "/metadata/labels", Value: desired.GetLabels()})
			}
		}
		payload, e := json.Marshal(ops)
		if e != nil {
			return nil, e
		}
		return resource.Patch(ctx, a.Target.Name, types.JSONPatchType, payload, metav1.PatchOptions{DryRun: dryRun, FieldValidation: "Strict"})
	default:
		return nil, fmt.Errorf("unsupported action")
	}
}
