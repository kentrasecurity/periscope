package llm

import "testing"

func TestEmptyOptionalObjectIsAbsent(t *testing.T) {
	d, e := decodeDecision([]byte(`{"diagnosis":"Use the allowed configuration value","risk":"low","actions":[{"id":"repair","type":"PatchResource","patch":[{"op":"replace","path":"/data/mode","value":"healthy"}],"object":{}}],"verification":{"type":"FieldEquals"},"evidenceRefs":[]}`), "unused")
	if e != nil {
		t.Fatal(e)
	}
	if d.Actions[0].Object != nil {
		t.Fatal("empty inapplicable object retained as an executable payload")
	}
}
