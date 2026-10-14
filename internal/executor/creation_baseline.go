package executor

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ObservedResultDigest freezes the full accepted server configuration, including
// defaults. An unassigned Pod's nodeName is subsequently set by the scheduler;
// an explicitly requested nodeName remains part of the approved baseline.
func ObservedResultDigest(u *unstructured.Unstructured, a api.Action) (string, error) {
	if u == nil {
		return "absent", nil
	}
	copy := u.DeepCopy()
	if copy.GetAPIVersion() == "v1" && copy.GetKind() == "Secret" {
		// Plan status is readable without Secret access; a hash of a weak
		// copied value could be brute-forced, so only key names are frozen.
		copy.Object["data"] = dataKeys(copy)
		delete(copy.Object, "stringData")
	}
	if a.Type == "CreateResource" && a.Target.APIVersion == "v1" && a.Target.Kind == "Pod" {
		if _, present, _ := unstructured.NestedFieldNoCopy(a.Object, "spec", "nodeName"); !present {
			unstructured.RemoveNestedField(copy.Object, "spec", "nodeName")
		}
	}
	return api.DigestTarget(copy)
}

func creationUnchanged(u *unstructured.Unstructured, a api.Action, j api.JournalEntry) bool {
	if a.Type != "CreateResource" || j.State == "Pending" {
		return true
	}
	if j.ServerResultDigest != "" {
		digest, err := ObservedResultDigest(u, a)
		return err == nil && digest == j.ServerResultDigest
	}
	// Pre-upgrade journals used a full result with only the assigned UID removed.
	if u == nil {
		return j.AfterDigest == "absent"
	}
	copy := u.DeepCopy()
	copy.SetUID("")
	digest, err := api.DigestTarget(copy)
	return err == nil && digest == j.AfterDigest
}

// fillSecret sets the values of a planned Secret at execution: random bytes
// or a copy of an owner-allowed source key. Authorization has already checked
// the sources against policy.
func fillSecret(ctx context.Context, r TargetReader, a api.Action, desired *unstructured.Unstructured) error {
	if len(a.SecretSources) == 0 || desired == nil {
		return nil
	}
	data := map[string]any{}
	for key, source := range a.SecretSources {
		if source.Generate > 0 {
			value := make([]byte, source.Generate)
			if _, err := rand.Read(value); err != nil {
				return err
			}
			data[key] = base64.StdEncoding.EncodeToString([]byte(base64.RawURLEncoding.EncodeToString(value)))
			continue
		}
		from, err := r.Get(ctx, api.TargetRef{APIVersion: "v1", Kind: "Secret", Namespace: a.Target.Namespace, Name: source.FromSecret})
		if err != nil {
			return fmt.Errorf("source Secret %s unavailable", source.FromSecret)
		}
		value, ok, _ := unstructured.NestedString(from.Object, "data", source.FromKey)
		if !ok {
			return fmt.Errorf("source Secret %s has no key %s", source.FromSecret, source.FromKey)
		}
		data[key] = value // already base64, as stored
	}
	desired.Object["data"] = data
	return nil
}
