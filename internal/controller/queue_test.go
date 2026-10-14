package controller

import (
	"github.com/kentrasecurity/periscope/internal/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"testing"
)

func TestQueueMapsPlanAndTaskEvents(t *testing.T) {
	task := &unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{"name": "repair", "namespace": "demo"}}}
	if got := EventTask(kube.TaskGVR, task); got != "demo/repair" {
		t.Fatalf("task key %q", got)
	}
	plan := task.DeepCopy()
	plan.Object["spec"] = map[string]any{"taskRef": map[string]any{"name": "repair"}}
	if got := EventTask(kube.PlanGVR, plan); got != "demo/repair" {
		t.Fatalf("plan key %q", got)
	}
	if got := EventTask(kube.ApprovalGVR, task); got != "" {
		t.Fatalf("approval must trigger cached tasks, not its own name: %q", got)
	}
}
