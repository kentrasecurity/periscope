package kube

import (
	"context"
	"encoding/json"
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type Task struct {
	Object *unstructured.Unstructured
	Spec   api.TaskSpec
	Status api.TaskStatus
}
type Plan struct {
	Object *unstructured.Unstructured
	Spec   api.PlanSpec
	Status api.PlanStatus
}
type Approval struct {
	Object *unstructured.Unstructured
	Spec   api.ApprovalSpec
}

type InvestigatorBackend interface {
	GetTask(context.Context, string, string) (*Task, error)
	SaveTaskStatus(context.Context, *Task) error
	GetPlan(context.Context, string, string) (*Plan, error)
	CreatePlan(context.Context, string, string, api.PlanSpec) (*Plan, error)
}

func Decode(value any, into any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, into)
}
func JSONMap(value any) map[string]any {
	b, e := json.Marshal(value)
	if e != nil {
		panic(e)
	}
	var m map[string]any
	if e = json.Unmarshal(b, &m); e != nil {
		panic(e)
	}
	return m
}
func ParseTask(u *unstructured.Unstructured) (*Task, error) {
	t := &Task{Object: u}
	if e := Decode(u.Object["spec"], &t.Spec); e != nil {
		return nil, e
	}
	if s, ok := u.Object["status"]; ok {
		if e := Decode(s, &t.Status); e != nil {
			return nil, e
		}
	}
	return t, nil
}
func ParsePlan(u *unstructured.Unstructured) (*Plan, error) {
	p := &Plan{Object: u}
	if e := Decode(u.Object["spec"], &p.Spec); e != nil {
		return nil, e
	}
	if s, ok := u.Object["status"]; ok {
		if e := Decode(s, &p.Status); e != nil {
			return nil, e
		}
	}
	return p, nil
}
