package executor

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/testkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestSecretValuesAreFilledAtExecutionAndNeverDigested(t *testing.T) {
	b := testkit.NewMemory()
	b.PutResource(testkit.Resource("v1", "Secret", "demo", "db-template", "src", map[string]any{"data": map[string]any{"password": base64.StdEncoding.EncodeToString([]byte("from-template"))}}))
	a := api.Action{ID: "secret", Type: "CreateResource", Target: api.TargetRef{APIVersion: "v1", Kind: "Secret", Namespace: "demo", Name: "db"},
		Object:        map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "db", "namespace": "demo"}},
		SecretSources: map[string]api.SecretSource{"password": {FromSecret: "db-template", FromKey: "password"}, "token": {Generate: 32}}}
	planned := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "db", "namespace": "demo"}}}
	filled := planned.DeepCopy()
	if err := fillSecret(context.Background(), b, a, filled); err != nil {
		t.Fatal(err)
	}
	password, _ := base64.StdEncoding.DecodeString(filled.Object["data"].(map[string]any)["password"].(string))
	token, _ := base64.StdEncoding.DecodeString(filled.Object["data"].(map[string]any)["token"].(string))
	if string(password) != "from-template" || len(token) < 40 {
		t.Fatalf("values not filled: %q %d", password, len(token))
	}
	// Admission recomputes the plan result without values; it must match the write.
	withValues, _ := ResultDigest(filled, a)
	withoutValues, _ := ResultDigest(planned, a)
	if withValues != withoutValues {
		t.Fatal("result digest depends on Secret values")
	}
	other := filled.DeepCopy()
	if err := fillSecret(context.Background(), b, a, other); err != nil {
		t.Fatal(err)
	}
	first, _ := ObservedResultDigest(filled, a)
	second, _ := ObservedResultDigest(other, a)
	if first != second {
		t.Fatal("stored digest depends on Secret values")
	}
	extra := filled.DeepCopy()
	extra.Object["data"].(map[string]any)["admin"] = "eA=="
	if tampered, _ := ResultDigest(extra, a); tampered == withValues {
		t.Fatal("unplanned Secret key accepted")
	}
}
