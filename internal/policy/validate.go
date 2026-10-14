package policy

import (
	"encoding/json"
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"regexp"
	"strings"
)

func dangerous(kind string) bool {
	switch kind {
	case "Secret", "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "TokenReview", "SubjectAccessReview", "SelfSubjectAccessReview", "CustomResourceDefinition", "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
		return true
	}
	return false
}

func Pointer(path string) ([]string, error) {
	if !strings.HasPrefix(path, "/") || path == "/" {
		return nil, fmt.Errorf("non-root JSON pointer required")
	}
	parts := strings.Split(path[1:], "/")
	for i, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("empty pointer segment")
		}
		for j := 0; j < len(p); j++ {
			if p[j] == '~' {
				if j+1 >= len(p) || (p[j+1] != '0' && p[j+1] != '1') {
					return nil, fmt.Errorf("invalid pointer escape")
				}
				j++
			}
		}
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(p, "~1", "/"), "~0", "~")
	}
	return parts, nil
}

func protected(path string) bool {
	parts, e := Pointer(path)
	if e != nil {
		return true
	}
	if parts[0] == "metadata" || parts[0] == "status" || parts[0] == "apiVersion" || parts[0] == "kind" {
		return true
	}
	for _, part := range parts {
		switch part {
		case "metadata", "serviceAccount", "serviceAccountName", "securityContext", "automountServiceAccountToken", "volumes", "volumeMounts", "command", "args", "hostNetwork", "hostPID", "hostIPC", "nodeName", "envFrom", "valueFrom", "imagePullSecrets":
			return true
		}
	}
	return false
}
func valueAllowed(value any, r ValueRule) bool {
	b, _ := json.Marshal(value)
	for _, v := range r.Values {
		other, e := json.Marshal(v)
		if e == nil && string(b) == string(other) {
			return true
		}
	}
	if r.Minimum != nil && r.Maximum != nil {
		var n float64
		switch x := value.(type) {
		case float64:
			n = x
		case int:
			n = float64(x)
		case int64:
			n = float64(x)
		default:
			return false
		}
		return n >= *r.Minimum && n <= *r.Maximum
	}
	if r.Pattern != "" && r.MaxLength > 0 {
		s, ok := value.(string)
		if !ok || len(s) > r.MaxLength {
			return false
		}
		matched, e := regexp.MatchString("^(?:"+r.Pattern+")$", s)
		return e == nil && matched
	}
	return false
}

func AuthorizeAction(a api.Action, current *unstructured.Unstructured, c Config) error {
	if c.RBAC() {
		return validateRBACAction(a, current, c)
	}
	if a.ID == "" || len(a.ID) > 128 || dangerous(a.Target.Kind) {
		return fmt.Errorf("invalid action or protected resource")
	}
	cap, e := c.Find(a)
	if e != nil {
		return e
	}
	if a.Target.Namespace == "" || a.Target.Name == "" {
		return fmt.Errorf("explicit namespace and target required")
	}
	if current != nil {
		if current.GetAPIVersion() != a.Target.APIVersion || current.GetKind() != a.Target.Kind || current.GetNamespace() != a.Target.Namespace || current.GetName() != a.Target.Name || string(current.GetUID()) != a.Target.UID {
			return fmt.Errorf("target identity changed")
		}
	} else if a.Type != "CreateResource" {
		return fmt.Errorf("target absent")
	}
	switch a.Type {
	case "PatchResource":
		if len(a.Patch) < 1 || len(a.Patch) > 32 || a.Object != nil {
			return fmt.Errorf("invalid patch payload: operations=%d objectPresent=%t", len(a.Patch), a.Object != nil)
		}
		for _, p := range a.Patch {
			if protected(p.Path) {
				return fmt.Errorf("protected patch path %s", p.Path)
			}
			r, ok := cap.Paths[p.Path]
			if !ok {
				return fmt.Errorf("path not allowlisted")
			}
			if p.Op != "replace" && p.Op != "add" && p.Op != "test" {
				return fmt.Errorf("only bounded add/replace/test operations are supported")
			}
			if !valueAllowed(p.Value, r) {
				return fmt.Errorf("patch value not permitted")
			}
		}
		result, err := BuildResult(a, current)
		if err != nil {
			return err
		}
		if protectedDescendants(current.Object["spec"], result.Object["spec"]) {
			return fmt.Errorf("patch changes protected descendant fields")
		}
	case "RestartWorkload":
		if a.Target.APIVersion != "apps/v1" || (a.Target.Kind != "Deployment" && a.Target.Kind != "StatefulSet" && a.Target.Kind != "DaemonSet") || len(a.Patch) != 0 || a.Object != nil {
			return fmt.Errorf("restart requires an apps/v1 workload and no arbitrary payload")
		}
	case "CreateResource":
		if current != nil || a.Target.UID != "" || cap.CreateObject == nil || len(a.Patch) != 0 {
			return fmt.Errorf("create requires an absent target and administrator-reviewed object")
		}
		want, _ := api.Hash(cap.CreateObject)
		got, _ := api.Hash(a.Object)
		if want != got {
			return fmt.Errorf("create object differs from administrator template")
		}
	case "DeleteResource":
		if a.Target.UID == "" || len(a.Patch) != 0 || a.Object != nil || !cap.RequireApproval {
			return fmt.Errorf("delete requires UID, no payload and mandatory human approval")
		}
	default:
		return fmt.Errorf("unknown action type")
	}
	return nil
}

func protectedDescendants(before, after any) bool {
	old, oldMap := before.(map[string]any)
	next, nextMap := after.(map[string]any)
	if oldMap || nextMap {
		keys := map[string]bool{}
		for key := range old {
			keys[key] = true
		}
		for key := range next {
			keys[key] = true
		}
		for key := range keys {
			switch key {
			case "metadata", "serviceAccount", "serviceAccountName", "securityContext", "automountServiceAccountToken", "volumes", "volumeMounts", "command", "args", "hostNetwork", "hostPID", "hostIPC", "nodeName", "envFrom", "valueFrom", "imagePullSecrets":
				a, _ := api.Hash(old[key])
				b, _ := api.Hash(next[key])
				if a != b {
					return true
				}
			}
			if key == "containers" || key == "initContainers" || key == "env" {
				a, _ := old[key].([]any)
				b, _ := next[key].([]any)
				if len(a) != len(b) {
					return true
				}
				for n := range a {
					left, _ := a[n].(map[string]any)
					right, _ := b[n].(map[string]any)
					if left["name"] != right["name"] {
						return true
					}
				}
			}
			if protectedDescendants(old[key], next[key]) {
				return true
			}
		}
		return false
	}
	a, aList := before.([]any)
	b, bList := after.([]any)
	if aList || bList {
		limit := len(a)
		if len(b) > limit {
			limit = len(b)
		}
		for n := 0; n < limit; n++ {
			var x, y any
			if n < len(a) {
				x = a[n]
			}
			if n < len(b) {
				y = b[n]
			}
			if protectedDescendants(x, y) {
				return true
			}
		}
	}
	return false
}

func ValidatePlan(task api.TaskSpec, p api.PlanSpec, c Config) error {
	if task.Mode == "Automatic" && !c.RBAC() {
		return fmt.Errorf("automatic requires RBAC authorization mode")
	}
	if task.Mode != "HumanApproved" && task.Mode != "Propose" && task.Mode != "Automatic" {
		return fmt.Errorf("mode does not permit action planning")
	}
	if p.PolicyDigest != PolicyDigest(c) || len(p.Actions) == 0 || len(p.Actions) > api.MaxActions {
		return fmt.Errorf("invalid policy or action count")
	}
	if task.Scope != nil {
		if c.CoordinationNamespace == "" {
			return fmt.Errorf("scoped execution requires common coordination namespace")
		}
		if !task.Scope.Contains(p.TargetRef) {
			return fmt.Errorf("plan target outside task scope")
		}
	} else if p.TargetRef.APIVersion != task.TargetRef.APIVersion || p.TargetRef.Kind != task.TargetRef.Kind || p.TargetRef.Name != task.TargetRef.Name || p.TargetRef.Namespace != task.TargetRef.Namespace {
		return fmt.Errorf("plan changed task target")
	}
	if p.Verification.TimeoutSeconds < 1 || p.Verification.TimeoutSeconds > 1800 || p.Verification.StableWindowSeconds < 1 || p.Verification.StableWindowSeconds > 600 || p.Verification.StableWindowSeconds > p.Verification.TimeoutSeconds {
		return fmt.Errorf("invalid verification bounds")
	}
	bindings, bindingErr := api.ResolveBindings(p)
	if bindingErr != nil {
		return bindingErr
	}
	for _, check := range p.Checks {
		if check.StableWindowSeconds > p.Verification.StableWindowSeconds || check.TimeoutSeconds > p.Verification.TimeoutSeconds {
			return fmt.Errorf("plan weakened original check timing")
		}
	}
	seen := map[string]bool{}
	for _, a := range p.Actions {
		if (a.Type == "CreateResource" || a.Type == "DeleteResource") && len(p.Actions) != 1 && len(p.Targets) == 0 {
			return fmt.Errorf("create/delete plans require one independently verifiable action")
		}
		if seen[a.ID] {
			return fmt.Errorf("duplicate action ID")
		}
		seen[a.ID] = true
		if len(p.Targets) == 0 && a.Target != p.TargetRef {
			return fmt.Errorf("actions must target the resolved task resource")
		}
		if len(p.Targets) > 0 {
			if a.Type == "CreateResource" && task.Scope != nil {
				desired, err := BuildResult(a, nil)
				if err != nil || !task.Scope.Matches(a.Target, desired) {
					return fmt.Errorf("created object outside task resource selector")
				}
			}
			binding, ok := bindings[a.BindingID]
			if !ok || binding.Target != a.Target {
				return fmt.Errorf("action target differs from exact binding")
			}
			if task.Scope != nil {
				if !task.Scope.Contains(a.Target) {
					return fmt.Errorf("action outside task scope")
				}
			} else if a.Target.APIVersion != task.TargetRef.APIVersion || a.Target.Kind != task.TargetRef.Kind || a.Target.Name != task.TargetRef.Name || a.Target.Namespace != task.TargetRef.Namespace {
				return fmt.Errorf("related writes require owner scoped task")
			}
		}
		cap, e := c.Find(a)
		if e != nil {
			return e
		}
		if !c.RBAC() && dangerous(a.Target.Kind) {
			return fmt.Errorf("protected resource")
		}
		if (cap.RequireApproval || cap.Risk != "low") && task.Mode != "HumanApproved" && task.Mode != "Propose" && task.Mode != "Automatic" {
			return fmt.Errorf("human approval required")
		}
		if p.Verification.HealthURL != "" && p.Verification.HealthURL != cap.HealthURL {
			return fmt.Errorf("health URL is not administrator-approved")
		}
		if cap.HealthURL != "" && p.Verification.HealthURL != cap.HealthURL {
			return fmt.Errorf("required application health verification missing")
		}
	}
	switch p.Verification.Type {
	case "ResourceHealthy":
		if p.TargetRef.Kind == "Pod" || p.TargetRef.Kind == "Deployment" {
			return fmt.Errorf("workload recovery requires its complete workload verifier")
		}
	case "PodRecovery":
		if p.TargetRef.APIVersion != "v1" || p.TargetRef.Kind != "Pod" {
			return fmt.Errorf("PodRecovery requires v1 Pod")
		}
	case "DeploymentRecovery":
		if p.TargetRef.Kind != "Deployment" {
			return fmt.Errorf("wrong recovery verifier")
		}
	case "FieldEquals":
		if p.TargetRef.Kind == "Deployment" || p.TargetRef.Kind == "Pod" {
			return fmt.Errorf("workload recovery requires workload verification")
		}
		if _, e := Pointer(p.Verification.Path); e != nil {
			return e
		}
		found := false
		for _, a := range p.Actions {
			for _, op := range a.Patch {
				x, _ := api.Hash(op.Value)
				y, _ := api.Hash(p.Verification.Expected)
				if op.Path == p.Verification.Path && x == y {
					found = true
				}
			}
		}
		if !found && !c.RBAC() {
			return fmt.Errorf("field verification must bind a proposed repair")
		}
	case "ResourceAbsent":
		for _, a := range p.Actions {
			if a.Type != "DeleteResource" {
				return fmt.Errorf("absence verification requires delete")
			}
		}
	case "ResourceExists":
		for _, a := range p.Actions {
			if a.Type != "CreateResource" {
				return fmt.Errorf("existence verification requires create")
			}
		}
	default:
		return fmt.Errorf("unsupported recovery verifier")
	}
	return nil
}
