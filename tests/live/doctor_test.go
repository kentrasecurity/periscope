//go:build live

// Package live runs the real investigator, executor and model provider against
// a simulated namespace holding three faults.
// It needs no cluster and makes real, billed model calls:
//
//	DOCTOR_PROVIDER=openai DOCTOR_API_KEY_FILE=./key go test -tags live -v -timeout 30m ./tests/live
//
// DOCTOR_MODEL overrides the provider's default model.
package live

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/controller"
	"github.com/kentrasecurity/periscope/internal/evidence"
	"github.com/kentrasecurity/periscope/internal/executor"
	"github.com/kentrasecurity/periscope/internal/llm"
	"github.com/kentrasecurity/periscope/internal/policy"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

const ns = "agent-operator-test"

// cluster is an in-memory namespace whose "kubelet" (settle) derives
// ReplicaSets, Pods, Events and workload status from Deployment templates.
type cluster struct {
	*testkit.Memory
	logs     map[string]string
	revision map[string]string
	now      time.Time
}

func (c *cluster) NamespacedResources(context.Context) ([]api.ResourceSelector, error) {
	return []api.ResourceSelector{{APIVersion: "v1", Kind: "Pod"}, {APIVersion: "apps/v1", Kind: "Deployment"}, {APIVersion: "apps/v1", Kind: "ReplicaSet"}, {APIVersion: "v1", Kind: "Service"}, {APIVersion: "v1", Kind: "ConfigMap"}, {APIVersion: "v1", Kind: "Event"}}, nil
}

func (c *cluster) List(ctx context.Context, version, kind, namespace, selector string) ([]*unstructured.Unstructured, error) {
	items, err := c.Memory.List(ctx, version, kind, namespace, selector)
	if err != nil || selector == "" || kind == "Event" {
		return items, err
	}
	parsed, err := labels.Parse(selector)
	if err != nil {
		return items, nil // field selectors; callers filter again
	}
	out := items[:0]
	for _, u := range items {
		if parsed.Matches(labels.Set(u.GetLabels())) {
			out = append(out, u)
		}
	}
	return out, nil
}

func (c *cluster) Logs(_ context.Context, namespace, pod, container string, previous bool, _ int64) (string, error) {
	if log, ok := c.logs[pod+"/"+container]; ok && !previous {
		return log, nil
	}
	return "", fmt.Errorf("container %q in pod %q is waiting to start", container, pod)
}

func deployment(name string, container map[string]any) *unstructured.Unstructured {
	labels := map[string]any{"app.kubernetes.io/name": name}
	d := testkit.Resource("apps/v1", "Deployment", ns, name, name+"-uid", map[string]any{"spec": map[string]any{
		"replicas": int64(1), "selector": map[string]any{"matchLabels": labels},
		"template": map[string]any{"metadata": map[string]any{"labels": labels}, "spec": map[string]any{"automountServiceAccountToken": false, "containers": []any{container}}},
	}})
	d.SetLabels(map[string]string{"app.kubernetes.io/name": name})
	return d
}

func newCluster() *cluster {
	c := &cluster{Memory: testkit.NewMemory(), logs: map[string]string{}, revision: map[string]string{}, now: time.Now().UTC()}
	c.PutResource(deployment("doctor-image", map[string]any{"name": "web", "image": "nginx:1.27-does-not-exist", "ports": []any{map[string]any{"containerPort": int64(80)}}}))
	c.PutResource(testkit.Resource("v1", "ConfigMap", ns, "doctor-settings", "settings-uid", map[string]any{"data": map[string]any{"greeting": "hello"}}))
	c.PutResource(deployment("doctor-config", map[string]any{"name": "app", "image": "busybox:1.36", "command": []any{"sh", "-c", `echo "$GREETING"; exec sleep 3600`},
		"env": []any{map[string]any{"name": "GREETING", "valueFrom": map[string]any{"configMapKeyRef": map[string]any{"name": "doctor-settings", "key": "greating"}}}}}))
	c.PutResource(deployment("doctor-web", map[string]any{"name": "web", "image": "nginx:1.27", "ports": []any{map[string]any{"containerPort": int64(80)}}}))
	c.PutResource(testkit.Resource("v1", "Service", ns, "doctor-service", "service-uid", map[string]any{"spec": map[string]any{
		"selector": map[string]any{"app.kubernetes.io/name": "doctor-wbe"}, "ports": []any{map[string]any{"port": int64(80), "targetPort": int64(80), "protocol": "TCP"}}}}))
	c.settle()
	return c
}

func (c *cluster) event(object *unstructured.Unstructured, reason, message string) {
	name := object.GetName() + "." + strings.ToLower(reason)
	c.PutResource(testkit.Resource("v1", "Event", ns, name, name+"-uid", map[string]any{
		"type": "Warning", "reason": reason, "message": message, "count": int64(5),
		"firstTimestamp": c.now.Add(-5 * time.Minute).Format(time.RFC3339), "lastTimestamp": c.now.Format(time.RFC3339),
		"involvedObject": map[string]any{"apiVersion": object.GetAPIVersion(), "kind": object.GetKind(), "name": object.GetName(), "namespace": ns, "uid": string(object.GetUID())},
	}))
}

// waiting returns the reason and message a kubelet would report for container.
func (c *cluster) waiting(container map[string]any) (string, string) {
	image, _ := container["image"].(string)
	if strings.Contains(image, "does-not-exist") {
		return "ImagePullBackOff", fmt.Sprintf(`Back-off pulling image "%s": ErrImagePull: docker.io/library/%s: not found`, image, image)
	}
	env, _ := container["env"].([]any)
	for _, e := range env {
		ref, found, _ := unstructured.NestedMap(e.(map[string]any), "valueFrom", "configMapKeyRef")
		if !found {
			continue
		}
		cm, err := c.Get(context.Background(), api.TargetRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: ns, Name: ref["name"].(string)})
		if err != nil {
			return "CreateContainerConfigError", fmt.Sprintf("configmap %q not found", ref["name"])
		}
		if _, ok, _ := unstructured.NestedString(cm.Object, "data", ref["key"].(string)); !ok {
			return "CreateContainerConfigError", fmt.Sprintf("couldn't find key %s in ConfigMap %s/%s", ref["key"], ns, ref["name"])
		}
	}
	return "", ""
}

func (c *cluster) settle() {
	for key, d := range c.Resources {
		if d.GetKind() != "Deployment" {
			continue
		}
		template, _, _ := unstructured.NestedMap(d.Object, "spec", "template")
		hash, _ := api.Hash(template)
		hash = hash[7:17]
		if old, ok := c.revision[key]; ok && old != hash {
			d.SetGeneration(d.GetGeneration() + 1)
			for k, u := range c.Resources {
				if (u.GetKind() == "Pod" || u.GetKind() == "ReplicaSet" || u.GetKind() == "Event") && strings.HasPrefix(u.GetName(), d.GetName()+"-"+old) {
					delete(c.Resources, k)
				}
			}
		}
		c.revision[key] = hash
		rsName := d.GetName() + "-" + hash
		controller := func(u *unstructured.Unstructured) map[string]any {
			return map[string]any{"apiVersion": u.GetAPIVersion(), "kind": u.GetKind(), "name": u.GetName(), "uid": string(u.GetUID()), "controller": true}
		}
		podLabels, _, _ := unstructured.NestedStringMap(template, "metadata", "labels")
		rs := testkit.Resource("apps/v1", "ReplicaSet", ns, rsName, rsName+"-uid", map[string]any{"spec": map[string]any{"replicas": int64(1), "template": template}})
		rs.Object["metadata"].(map[string]any)["ownerReferences"] = []any{controller(d)}
		rs.SetLabels(podLabels)
		podName := rsName + "-x7k2p"
		spec, _, _ := unstructured.NestedMap(template, "spec")
		containers, _, _ := unstructured.NestedSlice(spec, "containers")
		statuses, ready := []any{}, true
		pod := testkit.Resource("v1", "Pod", ns, podName, podName+"-uid", map[string]any{"spec": spec})
		pod.Object["metadata"].(map[string]any)["ownerReferences"] = []any{controller(rs)}
		pod.SetLabels(podLabels)
		pod.SetCreationTimestamp(testkit.Timestamp(c.now.Add(-5 * time.Minute)))
		for _, raw := range containers {
			container := raw.(map[string]any)
			name, image := container["name"].(string), container["image"].(string)
			reason, message := c.waiting(container)
			status := map[string]any{"name": name, "image": image, "ready": reason == "", "restartCount": int64(0)}
			if reason != "" {
				ready = false
				status["state"] = map[string]any{"waiting": map[string]any{"reason": reason, "message": message}}
				if reason == "ImagePullBackOff" {
					c.event(pod, "Failed", "Failed to pull image \""+image+"\": "+message)
				} else {
					c.event(pod, "Failed", "Error: "+message)
				}
			} else {
				status["state"] = map[string]any{"running": map[string]any{"startedAt": c.now.Add(-4 * time.Minute).Format(time.RFC3339)}}
				status["started"] = true
				status["containerID"] = "containerd://" + podName + "-" + name
				status["imageID"] = "docker.io/library/" + image + "@sha256:0f"
				c.logs[podName+"/"+name] = "started " + image + "\n"
			}
			statuses = append(statuses, status)
		}
		readyValue, phase := "False", "Pending"
		var count int64
		if ready {
			readyValue, phase, count = "True", "Running", 1
		}
		pod.Object["status"] = map[string]any{"phase": phase, "containerStatuses": statuses, "conditions": []any{
			map[string]any{"type": "PodScheduled", "status": "True"}, map[string]any{"type": "Ready", "status": readyValue}, map[string]any{"type": "ContainersReady", "status": readyValue}}}
		rs.Object["status"] = map[string]any{"replicas": int64(1), "readyReplicas": count, "availableReplicas": count, "observedGeneration": int64(1)}
		available := map[string]any{"type": "Available", "status": readyValue, "reason": "MinimumReplicasAvailable"}
		if !ready {
			available["reason"], available["message"] = "MinimumReplicasUnavailable", "Deployment does not have minimum availability."
		}
		d.Object["status"] = map[string]any{"observedGeneration": d.GetGeneration(), "replicas": int64(1), "updatedReplicas": int64(1), "readyReplicas": count, "availableReplicas": count, "unavailableReplicas": 1 - count, "conditions": []any{available}}
		c.PutResource(rs)
		c.PutResource(pod)
	}
}

// broken lists the faults the simulated namespace still has.
func (c *cluster) broken() []string {
	out := []string{}
	for _, name := range []string{"doctor-image", "doctor-config"} {
		d := c.Resources[ns+"/"+name]
		if ok, _, _ := executor.CheckResourceHealth(d); !ok {
			out = append(out, "Deployment/"+name)
		}
	}
	service := c.Resources[ns+"/doctor-service"]
	selector, _, _ := unstructured.NestedStringMap(service.Object, "spec", "selector")
	if selector["app.kubernetes.io/name"] != "doctor-web" || len(selector) != 1 {
		out = append(out, fmt.Sprintf("Service/doctor-service selector=%v", selector))
	}
	return out
}

func TestDoctorLive(t *testing.T) {
	keyFile := os.Getenv("DOCTOR_API_KEY_FILE")
	if keyFile == "" {
		t.Skip("DOCTOR_API_KEY_FILE not set")
	}
	provider := os.Getenv("DOCTOR_PROVIDER")
	if provider == "" {
		provider = "openai"
	}
	model, err := llm.New(llm.Config{Provider: provider, Model: os.Getenv("DOCTOR_MODEL"), APIKeyFile: keyFile, MaxOutputTokens: 16000})
	if err != nil {
		t.Fatal(err)
	}
	c := newCluster()
	grace := 0
	task := c.PutTask(ns, "doctor", "doctor-uid", api.TaskSpec{
		Mode:  "Observe",
		Scope: &api.Scope{Namespaces: []string{ns}},
		Objective: "Keep the application workloads in this namespace healthy. For each failing workload or Service, find the root cause from status, Events and logs, " +
			"and repair the owning template or the misconfigured resource with the smallest change that restores the intended behaviour. Preserve images' intended " +
			"application, configuration intent and security settings; never delete data or remove required configuration to pass checks.",
		Monitoring:    &api.Monitoring{IntervalSeconds: 30, GracePeriodSeconds: &grace},
		Limits:        api.Limits{DeadlineSeconds: 600, MaxModelCalls: 12, MaxToolCalls: 60},
		HealingLimits: &api.HealingLimits{MaxAttemptsPerIncident: 3, RetryCooldownSeconds: 30, WindowSeconds: 3600, MaxModelCallsPerWindow: 60, MaxToolCallsPerWindow: 400},
	})
	task.Object.SetCreationTimestamp(testkit.Timestamp(c.now.Add(-time.Hour)))
	task.Object.SetGeneration(1)
	p := policy.Config{Authorization: "RBAC", CoordinationNamespace: ns, Namespaces: []string{ns}}
	checker := executor.CheckEvaluator{Reader: c, Pods: c}
	inv := &controller.Investigator{Backend: c, Model: model, Policy: p, Checker: checker, Collector: evidence.Collector{Reader: c, Policy: p, MaxToolCalls: 30}}
	// Both components use the real clock: stable windows and retry cooldowns pass in real time.
	ex := &executor.Executor{Backend: c, Policy: p, Checker: checker}
	ctx := context.Background()
	elapse := func(d time.Duration) {
		time.Sleep(d)
		past := time.Now().Add(-time.Hour)
		task.Status.LastCheckedAt = &past
	}

	t.Logf("faults before: %v", c.broken())
	for round := 0; round < 8 && (round == 0 || strings.Contains(task.Status.Report, "diagnosis pending")); round++ {
		if err := inv.Reconcile(ctx, ns, "doctor"); err != nil {
			t.Fatalf("observe reconcile: %v", err)
		}
		t.Logf("observe round %d: phase=%s modelCalls=%d", round, task.Status.Phase, task.Status.Budget.ModelCalls)
		elapse(0)
	}
	t.Logf("OBSERVE REPORT:\n%s", task.Status.Report)
	if c.Mutations != 0 || len(c.Plans) != 0 {
		t.Fatal("Observe wrote to the namespace")
	}

	task.Spec.Mode = "Automatic"
	task.Object.SetGeneration(2)
	for round := 0; round < 90 && (round == 0 || len(c.broken()) > 0 || task.Status.Phase != "Succeeded" && task.Status.Phase != "Monitoring"); round++ {
		if err := inv.Reconcile(ctx, ns, "doctor"); err != nil {
			t.Fatalf("investigator reconcile: %v", err)
		}
		if err := ex.Reconcile(ctx, ns, "doctor"); err != nil {
			t.Fatalf("executor reconcile: %v", err)
		}
		c.settle()
		t.Logf("repair round %d: phase=%s modelCalls=%d broken=%v report=%.160s", round, task.Status.Phase, task.Status.Budget.ModelCalls, c.broken(), task.Status.Report)
		elapse(10 * time.Second)
	}
	for _, plan := range c.Plans {
		t.Logf("PLAN %s: %s", plan.Object.GetName(), plan.Spec.Diagnosis)
		raw, _ := json.Marshal(map[string]any{"target": plan.Spec.TargetRef, "verification": plan.Spec.Verification, "checks": plan.Spec.Checks, "status": plan.Status})
		t.Logf("  %s", raw)
		for _, a := range plan.Spec.Actions {
			t.Logf("  %s %s/%s %+v", a.Type, a.Target.Kind, a.Target.Name, a.Patch)
		}
	}
	if left := c.broken(); len(left) > 0 {
		t.Fatalf("faults left after repair: %v\n%s", left, task.Status.Report)
	}
	image, _, _ := unstructured.NestedSlice(c.Resources[ns+"/doctor-image"].Object, "spec", "template", "spec", "containers")
	if !strings.HasPrefix(image[0].(map[string]any)["image"].(string), "nginx:") {
		t.Fatalf("image repair changed the application: %v", image[0])
	}
	if _, ok, _ := unstructured.NestedString(c.Resources[ns+"/doctor-settings"].Object, "data", "greeting"); !ok {
		t.Fatal("configuration intent lost")
	}
}
