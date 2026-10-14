package evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONAndQuotedCredentialsRedacted(t *testing.T) {
	for _, input := range []string{`{"password":"database-password","api_key":"other-vendor-credential"}`, `prefix {"password": "database-password", "api_key": "other-vendor-credential"}`, `{"nested":{"password":"database-password with spaces and \"quote\""}}`, `password='database-password with spaces' api_key=other-vendor-credential`} {
		got := Redact(input)
		if strings.Contains(got, "database-password") || strings.Contains(got, "other-vendor-credential") {
			t.Fatalf("credential leaked: %s", got)
		}
		if json.Valid([]byte(input)) && !json.Valid([]byte(got)) {
			t.Fatal("JSON redaction damaged document")
		}
	}
}

func TestPodTokenMountBooleanSurvivesWithoutLeakingCredentials(t *testing.T) {
	input := `{"automountServiceAccountToken":false,"my_password":"sensitive-password","access_token":"sensitive-token"}`
	got := Redact(input)
	if !strings.Contains(got, `"automountServiceAccountToken":false`) || strings.Contains(got, "sensitive-password") || strings.Contains(got, "sensitive-token") {
		t.Fatalf("invalid flag/credential redaction: %s", got)
	}
	projected := sanitize(map[string]any{"automountServiceAccountToken": false, "access_token": "sensitive-token"}).(map[string]any)
	if projected["automountServiceAccountToken"] != false || projected["access_token"] != "[REDACTED]" {
		t.Fatal("security flag lost from evidence")
	}
}

func TestReferenceNamesSurviveRedactionButValuesDoNot(t *testing.T) {
	spec := map[string]any{"volumes": []any{map[string]any{"name": "creds", "secret": map[string]any{"secretName": "db-secrt"}}}, "imagePullSecrets": []any{map[string]any{"name": "registry"}}, "containers": []any{map[string]any{"name": "app", "envFrom": []any{map[string]any{"secretRef": map[string]any{"name": "app-env"}}}, "env": []any{map[string]any{"name": "DB_PASSWORD", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "db", "key": "password"}}}, map[string]any{"name": "API_TOKEN", "value": "literal-canary"}}}}}
	raw, _ := json.Marshal(sanitize(spec))
	s := string(raw)
	for _, want := range []string{"db-secrt", "registry", "app-env", `"name":"db"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("reference %s hidden from diagnosis: %s", want, s)
		}
	}
	if strings.Contains(s, "literal-canary") {
		t.Fatal("literal credential exposed")
	}
	action := `{"op":"replace","path":"/spec/template/spec/volumes/0/secret","value":{"secretName":"db-secret"}}`
	if Redact(action) != action {
		t.Fatalf("reference repair would be rejected as sensitive: %s", Redact(action))
	}
	if strings.Contains(Redact(`{"db_password":"value-canary"}`), "value-canary") {
		t.Fatal("credential assignment exposed")
	}
}

func TestScalarUnderReferenceKeyStaysRedacted(t *testing.T) {
	raw, _ := json.Marshal(sanitize(map[string]any{"data": map[string]any{"secret": "scalar-canary"}}))
	if strings.Contains(string(raw), "scalar-canary") || strings.Contains(Redact(`secret=scalar-canary`), "scalar-canary") {
		t.Fatalf("scalar credential exposed: %s", raw)
	}
}
