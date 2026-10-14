package api

import (
	"fmt"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
)

type ResourceSelector struct {
	APIVersion    string `json:"apiVersion,omitempty"`
	Kind          string `json:"kind,omitempty"`
	Name          string `json:"name,omitempty"`
	LabelSelector string `json:"labelSelector,omitempty"`
}
type Scope struct {
	Namespaces []string           `json:"namespaces"`
	Resources  []ResourceSelector `json:"resources,omitempty"`
}

func (s Scope) Validate() error {
	if len(s.Namespaces) == 0 || len(s.Namespaces) > 16 || len(s.Resources) > 32 {
		return fmt.Errorf("explicit bounded scope required")
	}
	seen := map[string]bool{}
	for _, ns := range s.Namespaces {
		if ns == "" || ns == "*" || seen[ns] || len(validation.IsDNS1123Label(ns)) > 0 {
			return fmt.Errorf("invalid scope namespace")
		}
		seen[ns] = true
	}
	for _, r := range s.Resources {
		if (r.APIVersion == "") != (r.Kind == "") {
			return fmt.Errorf("resource apiVersion/kind must be paired")
		}
		if _, err := labels.Parse(r.LabelSelector); err != nil {
			return err
		}
	}
	return nil
}
func (s Scope) Contains(t TargetRef) bool {
	ns := false
	for _, n := range s.Namespaces {
		if n == t.Namespace {
			ns = true
		}
	}
	if !ns {
		return false
	}
	if len(s.Resources) == 0 {
		return true
	}
	for _, r := range s.Resources {
		if (r.APIVersion == "" || r.APIVersion == t.APIVersion) && (r.Kind == "" || r.Kind == t.Kind) && (r.Name == "" || r.Name == t.Name) {
			return true
		}
	}
	return false
}
func (s Scope) Matches(t TargetRef, u *unstructured.Unstructured) bool {
	if !s.Contains(t) {
		return false
	}
	if len(s.Resources) == 0 {
		return true
	}
	for _, r := range s.Resources {
		if (r.APIVersion == "" || r.APIVersion == t.APIVersion) && (r.Kind == "" || r.Kind == t.Kind) && (r.Name == "" || r.Name == t.Name) {
			sel, err := labels.Parse(r.LabelSelector)
			if err == nil && (sel.Empty() || u != nil && sel.Matches(labels.Set(u.GetLabels()))) {
				return true
			}
		}
	}
	return false
}
