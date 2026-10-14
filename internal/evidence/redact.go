package evidence

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var tokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-(?:proj-|ant-)?[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
}

var credentialURL = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^\s/"\x27]*@`)

var assignments = regexp.MustCompile(`(?i)(["']?[A-Za-z0-9_-]*(?:password|passwd|api[_-]?key|access[_-]?token|authorization|token|secret)[A-Za-z0-9_-]*["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'[^']*'|[^\s,;}]+)`)

func Redact(s string) string {
	s = credentialURL.ReplaceAllString(s, `${1}[REDACTED]@`)
	s = assignments.ReplaceAllStringFunc(s, func(match string) string {
		prefix := assignments.FindStringSubmatch(match)[1]
		field := strings.Trim(strings.TrimSpace(prefix[:strings.LastIndexAny(prefix, ":=")]), "\"'")
		value := strings.TrimSpace(match[len(prefix):])
		// Booleans such as automountServiceAccountToken and references such as
		// secretName or secretKeyRef name objects; neither is credential material.
		if value == "true" || value == "false" || value == "null" || ReferenceField(field) || StructuralReference(field) && (strings.HasPrefix(value, "{") || strings.HasPrefix(value, "[")) {
			return match
		}
		return prefix + `"[REDACTED]"`
	})
	for _, p := range tokenPatterns {
		s = p.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}
func Bound(s string, maximum int) string {
	if maximum < 1 {
		return ""
	}
	if len(s) <= maximum {
		return s
	}
	end := maximum
	for end > 0 && !utf8.ValidString(s[:end]) {
		end--
	}
	return strings.ToValidUTF8(s[:end], "")
}

// BoundTail keeps the last maximum bytes of s. Logs end with the failure, so
// truncation must drop the oldest lines, not the newest.
func BoundTail(s string, maximum int) string {
	if maximum < 1 {
		return ""
	}
	if len(s) <= maximum {
		return s
	}
	start := len(s) - maximum
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	if newline := strings.IndexByte(s[start:], '\n'); newline >= 0 && newline < 256 {
		start += newline + 1
	}
	return "…" + s[start:]
}

// ReferenceField reports keys whose values name another object (secretName,
// secretKeyRef, tokenSecretRef, ...) or configure projected token volumes.
// Their values identify resources and are needed to diagnose and repair broken
// references, such as a Pod mounting a misspelled Secret.
func ReferenceField(k string) bool {
	s := strings.ToLower(strings.Trim(k, "\"'"))
	return strings.HasSuffix(s, "name") || strings.HasSuffix(s, "ref") || s == "serviceaccounttoken"
}

// StructuralReference reports keys that hold reference objects or lists, such
// as a Secret volume source or imagePullSecrets. They are exempt only when the
// value is an object or list; a scalar under the same key may be a credential.
func StructuralReference(k string) bool {
	switch strings.ToLower(strings.Trim(k, "\"'")) {
	case "secret", "secrets", "imagepullsecrets":
		return true
	}
	return false
}
