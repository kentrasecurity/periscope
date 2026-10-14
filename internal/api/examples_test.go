package api

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

// Every AgentTask shipped in examples/ and the live tests must pass the same
// validation as admission.
func TestExampleTasksAreValid(t *testing.T) {
	files, _ := filepath.Glob("../../examples/*.yaml")
	nested, _ := filepath.Glob("../../tests/e2e/suite/*.yaml")
	live := []string{}
	checked := 0
	for _, file := range append(append(files, nested...), live...) {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, doc := range bytes.Split(raw, []byte("\n---")) {
			var object struct {
				Kind     string `json:"kind"`
				Metadata struct {
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Spec TaskSpec `json:"spec"`
			}
			if err := yaml.Unmarshal(doc, &object); err != nil || object.Kind != "AgentTask" {
				continue
			}
			spec := object.Spec
			if spec.Limits == (Limits{}) {
				spec.Limits = DefaultLimits() // CRD default
			}
			if spec.Scope == nil && spec.TargetRef.Namespace == "" {
				spec.TargetRef.Namespace = object.Metadata.Namespace
			}
			if err := ValidateTask(spec); err != nil {
				t.Errorf("%s: %v", file, err)
			}
			checked++
		}
	}
	if checked < 2 {
		t.Fatalf("only %d example tasks found", checked)
	}
}
