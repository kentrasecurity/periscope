{{- define "periscope.name" -}}
{{- ternary .Release.Name (printf "%s-periscope" .Release.Name) (eq .Release.Name "periscope") | trunc 40 | trimSuffix "-" -}}
{{- end -}}
{{- define "periscope.namespaces" -}}
{{- if not .Values.policy.namespaces -}}
{{- fail "policy.namespaces must explicitly enroll at least one namespace" -}}
{{- end -}}
{{- range .Values.policy.namespaces -}}
{{- if or (eq . "") (eq . "*") -}}{{ fail "explicit enrolled namespaces required" }}{{- end -}}
{{- end -}}
{{- if ne .Values.policy.authorization "RBAC" -}}
{{- range concat .Values.policy.readRules .Values.policy.capabilities -}}
{{- if or (contains "*" .resource) (contains "/" .resource) (has .resource (list "secrets" "serviceaccounts" "roles" "rolebindings" "clusterroles" "clusterrolebindings" "customresourcedefinitions" "validatingwebhookconfigurations" "mutatingwebhookconfigurations" "validatingadmissionpolicies" "validatingadmissionpolicybindings" "certificatesigningrequests" "tokenreviews" "subjectaccessreviews" "selfsubjectaccessreviews" "selfsubjectrulesreviews" "localsubjectaccessreviews")) -}}
{{- fail "dangerous/wildcard/subresource policy grants are forbidden" -}}
{{- end -}}
{{- if not (has .namespace $.Values.policy.namespaces) -}}{{ fail "rule namespace must be enrolled" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
