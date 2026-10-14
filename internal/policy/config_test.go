package policy

import (
	"strings"
	"testing"
)

func TestConfigRejectsDangerousReadGrants(t *testing.T) {
	for _, resource := range []string{"secrets", "*", "pods/exec", "serviceaccounts/token"} {
		if _, e := Load(strings.NewReader(`{"namespaces":["demo"],"readRules":[{"apiVersion":"v1","kind":"ConfigMap","resource":"` + resource + `","namespace":"demo"}],"capabilities":[]}`)); e == nil {
			t.Fatalf("dangerous read grant accepted: %s", resource)
		}
	}
}
