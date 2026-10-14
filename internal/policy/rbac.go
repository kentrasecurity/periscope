package policy

import (
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"strings"
)

// RBAC decides permissions. These checks define the supported action protocol,
// preserving the identity and concurrency preconditions the human approved.
func validateRBACAction(a api.Action, u *unstructured.Unstructured, c Config) error {
	if a.ID == "" || len(a.ID) > 128 || a.Target.Name == "" || a.Target.Namespace == "" {
		return fmt.Errorf("explicit action and target required")
	}
	if _, err := c.Find(a); err != nil {
		return err
	}
	if strings.HasPrefix(a.Target.APIVersion, api.Group+"/") || (a.Target.Kind == "Lease" && strings.HasPrefix(a.Target.Name, "periscope-")) {
		return fmt.Errorf("operator approval/claim records are not repair targets")
	}
	if u != nil && api.IsOperatorInfrastructure(u.GetLabels()) || a.Object != nil && api.IsOperatorInfrastructure((&unstructured.Unstructured{Object: a.Object}).GetLabels()) {
		return fmt.Errorf("operator infrastructure is not a repair target")
	}
	if err := storageAction(a, u, c); err != nil {
		return err
	}
	if err := secretAction(a, c); err != nil {
		return err
	}
	if u != nil && (u.GetAPIVersion() != a.Target.APIVersion || u.GetKind() != a.Target.Kind || u.GetNamespace() != a.Target.Namespace || u.GetName() != a.Target.Name || string(u.GetUID()) != a.Target.UID) {
		return fmt.Errorf("target identity changed")
	}
	if u == nil && a.Type != "CreateResource" {
		return fmt.Errorf("target absent")
	}
	switch a.Type {
	case "PatchResource":
		if len(a.Patch) < 1 || len(a.Patch) > 32 || a.Object != nil {
			return fmt.Errorf("invalid patch payload")
		}
		for _, op := range a.Patch {
			if _, err := Pointer(op.Path); err != nil {
				return err
			}
			if op.Op != "add" && op.Op != "replace" && op.Op != "remove" && op.Op != "test" {
				return fmt.Errorf("unsupported patch operation")
			}
		}
		next, err := BuildResult(a, u)
		if err != nil {
			return err
		}
		if api.IsOperatorInfrastructure(next.GetLabels()) {
			return fmt.Errorf("operator infrastructure is not a repair target")
		}
		if next.GetAPIVersion() != u.GetAPIVersion() || next.GetKind() != u.GetKind() || next.GetNamespace() != u.GetNamespace() || next.GetName() != u.GetName() || next.GetUID() != u.GetUID() || next.GetResourceVersion() != u.GetResourceVersion() {
			return fmt.Errorf("patch changes target identity/version")
		}
		beforeStatus, _ := api.Hash(u.Object["status"])
		afterStatus, _ := api.Hash(next.Object["status"])
		if beforeStatus != afterStatus {
			return fmt.Errorf("status subresource is not a repair action")
		}
		beforeMeta, _, _ := unstructured.NestedMap(u.Object, "metadata")
		afterMeta, _, _ := unstructured.NestedMap(next.Object, "metadata")
		delete(beforeMeta, "annotations")
		delete(afterMeta, "annotations")
		delete(beforeMeta, "labels")
		delete(afterMeta, "labels")
		b, _ := api.Hash(beforeMeta)
		n, _ := api.Hash(afterMeta)
		if b != n {
			return fmt.Errorf("server metadata is immutable in repair actions")
		}
	case "RestartWorkload":
		if a.Target.APIVersion != "apps/v1" || (a.Target.Kind != "Deployment" && a.Target.Kind != "StatefulSet" && a.Target.Kind != "DaemonSet") || len(a.Patch) != 0 || a.Object != nil {
			return fmt.Errorf("invalid restart action")
		}
	case "CreateResource":
		if u != nil {
			return fmt.Errorf("CreateResource resolved target %s already exists; creation requires an absent target. For a related resource supply its explicit apiVersion/kind/namespace/name in action.target; omitting target selects the monitored resource", api.ResourceKey(a.Target))
		}
		if a.Target.UID != "" || a.Object == nil || len(a.Patch) != 0 {
			return fmt.Errorf("invalid create action")
		}
		if _, err := BuildResult(a, nil); err != nil {
			return err
		}
	case "DeleteResource":
		if a.Target.UID == "" || len(a.Patch) != 0 || a.Object != nil {
			return fmt.Errorf("invalid delete action")
		}
	default:
		return fmt.Errorf("unsupported action type")
	}
	return nil
}

// storageAction limits PersistentVolumeClaim writes to what the owner opted
// into: recreating claims that never bound, and growing a claim's request.
// PersistentVolumes are never repair targets.
func storageAction(a api.Action, u *unstructured.Unstructured, c Config) error {
	if a.Target.APIVersion != "v1" {
		return nil
	}
	if a.Target.Kind == "PersistentVolume" {
		return fmt.Errorf("PersistentVolumes are never repair targets; report the storage fault for owner action")
	}
	if a.Target.Kind != "PersistentVolumeClaim" {
		return nil
	}
	storage := c.Repairs.Storage
	if u == nil && a.Type != "CreateResource" {
		return fmt.Errorf("target absent")
	}
	switch a.Type {
	case "DeleteResource":
		if !storage.ReplaceUnboundClaims {
			return fmt.Errorf("deleting a PersistentVolumeClaim destroys its data and is not enabled (policy.repairs.storage.replaceUnboundClaims); report the storage fault for owner action")
		}
		phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
		volume, _, _ := unstructured.NestedString(u.Object, "spec", "volumeName")
		if phase != "Pending" || volume != "" {
			return fmt.Errorf("only a PersistentVolumeClaim that never bound (Pending, no volumeName) may be replaced; this one may hold data")
		}
	case "CreateResource":
		if !storage.ReplaceUnboundClaims {
			return fmt.Errorf("creating PersistentVolumeClaims is not enabled (policy.repairs.storage.replaceUnboundClaims)")
		}
	case "PatchResource":
		if !storage.ExpandClaims {
			return fmt.Errorf("changing PersistentVolumeClaims is not enabled (policy.repairs.storage.expandClaims)")
		}
		for _, op := range a.Patch {
			if op.Op == "test" {
				continue
			}
			if op.Op != "replace" || op.Path != "/spec/resources/requests/storage" {
				return fmt.Errorf("a PersistentVolumeClaim may only have spec.resources.requests.storage increased")
			}
			current, _, _ := unstructured.NestedString(u.Object, "spec", "resources", "requests", "storage")
			before, errBefore := resource.ParseQuantity(current)
			after, errAfter := resource.ParseQuantity(fmt.Sprint(op.Value))
			if errBefore != nil || errAfter != nil || after.Cmp(before) <= 0 {
				return fmt.Errorf("a PersistentVolumeClaim storage request may only grow (from %q)", current)
			}
		}
	default:
		return fmt.Errorf("unsupported PersistentVolumeClaim action")
	}
	return nil
}

// secretAction allows only the creation of a missing Secret whose values the
// executor fills from secretSources, when the owner enabled that mode.
func secretAction(a api.Action, c Config) error {
	isSecret := a.Target.APIVersion == "v1" && a.Target.Kind == "Secret"
	if !isSecret {
		if len(a.SecretSources) > 0 {
			return fmt.Errorf("secretSources apply only to a created Secret")
		}
		return nil
	}
	if a.Type != "CreateResource" {
		return fmt.Errorf("existing Secrets are never changed or deleted; report the credential fault for owner action")
	}
	if !c.SecretCreation(SecretsGenerate) && !c.SecretCreation(SecretsFromSource) {
		return fmt.Errorf("creating Secrets is not enabled (policy.repairs.secrets.create); report the missing Secret for owner action")
	}
	for _, field := range []string{"data", "stringData"} {
		if _, present := a.Object[field]; present {
			return fmt.Errorf("a created Secret must not carry %s: name each key in secretSources and the executor fills in the value", field)
		}
	}
	if kind, _ := a.Object["type"].(string); kind != "" && kind != "Opaque" {
		return fmt.Errorf("only Opaque Secrets may be created")
	}
	if len(a.SecretSources) == 0 || len(a.SecretSources) > 32 {
		return fmt.Errorf("a created Secret needs 1..32 keys in secretSources")
	}
	for key, source := range a.SecretSources {
		switch {
		case key == "" || len(key) > 253:
			return fmt.Errorf("invalid Secret key")
		case source.Generate != 0 && source.FromSecret == "" && source.FromKey == "":
			if !c.SecretCreation(SecretsGenerate) {
				return fmt.Errorf("generated Secret values are not enabled (policy.repairs.secrets.create)")
			}
			if source.Generate < 16 || source.Generate > 64 {
				return fmt.Errorf("generated Secret values need 16..64 random bytes")
			}
		case source.Generate == 0 && source.FromSecret != "" && source.FromKey != "":
			if !c.SecretCreation(SecretsFromSource) || !contains(c.Repairs.Secrets.Sources, source.FromSecret) {
				return fmt.Errorf("Secret %q is not an allowed source (policy.repairs.secrets.sources)", source.FromSecret)
			}
			if source.FromSecret == a.Target.Name {
				return fmt.Errorf("a Secret cannot be its own source")
			}
		default:
			return fmt.Errorf("secretSources.%s needs either generate or fromSecret and fromKey", key)
		}
	}
	return nil
}
