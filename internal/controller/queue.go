package controller

import (
	"context"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"log"
	"strings"
	"sync"
	"time"
)

func EventTask(gvr schema.GroupVersionResource, obj any) string {
	if deleted, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = deleted.Obj
	}
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return ""
	}
	name := u.GetName()
	if gvr == kube.PlanGVR {
		name, _, _ = unstructured.NestedString(u.Object, "spec", "taskRef", "name")
	}
	if gvr == kube.ApprovalGVR || name == "" || u.GetNamespace() == "" {
		return ""
	}
	return u.GetNamespace() + "/" + name
}

// QueueOptions bounds concurrency and per-reconcile time. A single task is
// never reconciled by two workers at once; distinct tasks proceed in parallel,
// so one long investigation does not stall monitoring of every other task.
type QueueOptions struct {
	Workers int
	Timeout time.Duration
}

// RunQueue uses namespace-scoped watches, relists on disconnection, and a
// periodic retry for verification and temporary failures. API preconditions
// and target claims fence concurrent writers.
func RunQueue(ctx context.Context, client dynamic.Interface, namespaces []string, reconcile func(context.Context, string, string) error, ready func(), options QueueOptions) error {
	if len(namespaces) == 0 {
		return fmt.Errorf("at least one enrolled namespace required")
	}
	if options.Workers < 1 || options.Workers > 64 {
		return fmt.Errorf("workers must be between 1 and 64")
	}
	if options.Timeout < 10*time.Second || options.Timeout > time.Hour {
		return fmt.Errorf("reconcile timeout must be between 10s and 1h")
	}
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
	defer queue.ShutDown()
	var syncs []cache.InformerSynced
	var tasks []cache.SharedIndexInformer
	for _, ns := range namespaces {
		if ns == "" || ns == "*" {
			return fmt.Errorf("explicit namespace required")
		}
		factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(client, 30*time.Second, ns, nil)
		ti := factory.ForResource(kube.TaskGVR).Informer()
		tasks = append(tasks, ti)
		for _, gvr := range []schema.GroupVersionResource{kube.TaskGVR, kube.PlanGVR, kube.ApprovalGVR, {Group: "", Version: "v1", Resource: "pods"}, {Group: "apps", Version: "v1", Resource: "deployments"}} {
			informer := factory.ForResource(gvr).Informer()
			if gvr.Group == kube.TaskGVR.Group {
				syncs = append(syncs, informer.HasSynced)
			}
			enqueue := func(obj any) {
				if gvr.Group == kube.TaskGVR.Group {
					if key := EventTask(gvr, obj); key != "" {
						queue.Add(key)
						return
					}
				}
				if gvr == kube.ApprovalGVR || gvr.Group != kube.TaskGVR.Group {
					for _, t := range ti.GetStore().List() {
						if key := EventTask(kube.TaskGVR, t); key != "" {
							queue.Add(key)
						}
					}
				}
			}
			if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{AddFunc: enqueue, UpdateFunc: func(old, next any) {
				before, bok := old.(*unstructured.Unstructured)
				after, aok := next.(*unstructured.Unstructured)
				if !bok || !aok {
					return
				}
				if gvr.Group != kube.TaskGVR.Group || gvr == kube.ApprovalGVR || before.GetGeneration() != after.GetGeneration() {
					enqueue(next)
					return
				}
				if gvr == kube.TaskGVR {
					a, _, _ := unstructured.NestedString(before.Object, "status", "planRef", "name")
					b, _, _ := unstructured.NestedString(after.Object, "status", "planRef", "name")
					if a != b {
						enqueue(next)
					}
				}
			}, DeleteFunc: enqueue}); err != nil {
				return err
			}
		}
		factory.Start(ctx.Done())
	}
	if !cache.WaitForCacheSync(ctx.Done(), syncs...) {
		return fmt.Errorf("cache sync cancelled")
	}
	ready()
	go func() { <-ctx.Done(); queue.ShutDown() }()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, ti := range tasks {
					for _, obj := range ti.GetStore().List() {
						if key := EventTask(kube.TaskGVR, obj); key != "" {
							queue.Add(key)
						}
					}
				}
			}
		}
	}()
	var workers sync.WaitGroup
	for range options.Workers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for processNext(ctx, queue, reconcile, options.Timeout) {
			}
		}()
	}
	workers.Wait()
	return nil
}

func processNext(ctx context.Context, queue workqueue.TypedRateLimitingInterface[string], reconcile func(context.Context, string, string) error, timeout time.Duration) bool {
	key, shutdown := queue.Get()
	if shutdown {
		return false
	}
	defer queue.Done(key)
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		queue.Forget(key)
		return true
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	err := reconcile(bounded, parts[0], parts[1])
	cancel()
	if err == nil {
		queue.Forget(key)
		return true
	}
	log.Printf("reconcile %s failed: %v; retrying", key, err)
	if queue.NumRequeues(key) < 8 {
		queue.AddRateLimited(key)
	} else {
		queue.Forget(key)
	}
	return true
}
