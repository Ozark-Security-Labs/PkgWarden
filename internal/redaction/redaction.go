package redaction

import (
	"regexp"
	"strings"
)

var (
	urlCredentialPattern       = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s:]+(?::[^/@\s]+)?@`)
	bearerPattern              = regexp.MustCompile(`(?i)(\bBearer\s+)[^\s,;]+`)
	secretAssignmentPattern    = regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:token|secret|password|api[_-]?key)[A-Za-z0-9_.-]*\s*[:=]\s*)[^\s,;]+`)
	xmlValueAfterSecretPattern = regexp.MustCompile(`(?i)((?:password|token|secret|api[_-]?key|auth)[^<>\n]*\bvalue\s*=\s*")[^"]+(")`)
	npmTokenPattern            = regexp.MustCompile(`\bnpm_[A-Za-z0-9][A-Za-z0-9_-]*`)
	placeholderPattern         = regexp.MustCompile(`\$\{\{[^}]+\}\}|\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%`)
	placeholderMarker          = "\x00PKGWARDEN_PLACEHOLDER_"
)

// EvidenceText redacts package-manager credential values while preserving
// enough surrounding syntax for reports to explain what was found.
func EvidenceText(value string) string {
	placeholders := placeholderPattern.FindAllString(value, -1)
	for i, placeholder := range placeholders {
		value = strings.Replace(value, placeholder, placeholderToken(i), 1)
	}

	value = urlCredentialPattern.ReplaceAllString(value, "${1}[REDACTED]@")
	value = bearerPattern.ReplaceAllString(value, "${1}[REDACTED]")
	value = xmlValueAfterSecretPattern.ReplaceAllString(value, "${1}[REDACTED]${2}")
	value = redactSecretAssignments(value)
	value = npmTokenPattern.ReplaceAllString(value, "[REDACTED]")

	for i, placeholder := range placeholders {
		value = strings.ReplaceAll(value, placeholderToken(i), placeholder)
	}
	return value
}

func redactSecretAssignments(value string) string {
	return secretAssignmentPattern.ReplaceAllStringFunc(value, func(match string) string {
		if strings.Contains(match, placeholderMarker) {
			return match
		}
		parts := secretAssignmentPattern.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}
		return parts[1] + "[REDACTED]"
	})
}

func placeholderToken(index int) string {
	return placeholderMarker + string(rune('A'+index)) + "\x00"
}
