package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

const DefaultFilename = ".pkgwarden.yml"

func Load(path string) (model.Policy, []model.Warning) {
	content, err := os.ReadFile(path)
	if err != nil {
		return model.EmptyPolicy(), []model.Warning{{Path: filepath.ToSlash(path), Message: err.Error()}}
	}
	parsed, parseWarnings := parsePolicyLines(filepath.ToSlash(filepath.Base(path)), content)
	return parsed, parseWarnings
}

func LoadOptional(target string, explicitPath string) (model.Policy, []model.Warning) {
	if explicitPath != "" {
		return Load(explicitPath)
	}
	path := filepath.Join(target, DefaultFilename)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return model.EmptyPolicy(), []model.Warning{}
		}
		return model.EmptyPolicy(), []model.Warning{{Path: DefaultFilename, Message: err.Error()}}
	}
	return Load(path)
}

func parsePolicyLines(path string, content []byte) (model.Policy, []model.Warning) {
	policy := model.EmptyPolicy()
	issues := []string{}
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	section := ""
	ruleList := ""
	registryList := ""
	firewallList := ""
	var currentSuppression *model.Suppression

	flushSuppression := func() {
		if currentSuppression == nil {
			return
		}
		if currentSuppression.RuleID != "" {
			if currentSuppression.Reason != "" {
				policy.Suppressions = append(policy.Suppressions, *currentSuppression)
			} else {
				issues = append(issues, "policy suppression missing reason")
			}
		} else {
			issues = append(issues, "policy suppression missing rule_id")
		}
		currentSuppression = nil
	}

	for _, raw := range lines {
		line := stripPolicyComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := leadingSpaces(line)
		trimmed := strings.TrimSpace(line)

		if indent == 0 {
			flushSuppression()
			ruleList = ""
			registryList = ""
			firewallList = ""
			key, value, ok := splitPolicyKeyValue(trimmed)
			if !ok {
				issues = append(issues, "policy line is not key/value: "+trimmed)
				continue
			}
			section = key
			switch key {
			case "strict":
				strict, ok := parsePolicyBool(value)
				if !ok {
					issues = append(issues, "invalid strict value: "+value)
					continue
				}
				policy.Strict = strict
			case "profiles":
				policy.Profiles = appendProfileValues(policy.Profiles, value, &issues)
			case "rules", "suppressions", "registries", "package_firewall":
			default:
				issues = append(issues, "unknown policy section: "+key)
			}
			continue
		}

		switch section {
		case "profiles":
			if value, ok := listItem(trimmed); ok {
				policy.Profiles = appendProfileValues(policy.Profiles, value, &issues)
			} else {
				issues = append(issues, "unknown policy key: profiles."+trimmed)
			}
		case "rules":
			key, value, ok := splitPolicyKeyValue(trimmed)
			if ok && (key == "enabled" || key == "disabled" || key == "severity") {
				ruleList = key
				appendRuleValues(&policy, key, value, &issues)
				continue
			}
			if value, ok := listItem(trimmed); ok {
				appendRuleValues(&policy, ruleList, value, &issues)
				continue
			}
			if ok && ruleList == "severity" {
				appendSeverityOverride(&policy, key, value, &issues)
				continue
			}
			issues = append(issues, "unknown policy key: rules."+trimmed)
		case "registries":
			key, value, ok := splitPolicyKeyValue(trimmed)
			if ok && key == "approved" {
				registryList = key
				appendRegistryValues(&policy, value)
				continue
			}
			if value, ok := listItem(trimmed); ok && registryList == "approved" {
				appendRegistryValues(&policy, value)
				continue
			}
			issues = append(issues, "unknown policy key: registries."+trimmed)
		case "package_firewall":
			key, value, ok := splitPolicyKeyValue(trimmed)
			if ok && key == "endpoints" {
				firewallList = key
				appendFirewallEndpointValues(&policy, value)
				continue
			}
			if ok && key == "default_cooldown_days" {
				setDefaultCooldownDays(&policy, value, &issues)
				continue
			}
			if value, ok := listItem(trimmed); ok && firewallList == "endpoints" {
				appendFirewallEndpointValues(&policy, value)
				continue
			}
			issues = append(issues, "unknown policy key: package_firewall."+trimmed)
		case "suppressions":
			if value, ok := listItem(trimmed); ok {
				flushSuppression()
				currentSuppression = &model.Suppression{}
				if key, fieldValue, ok := splitPolicyKeyValue(value); ok {
					if !setSuppressionField(currentSuppression, key, fieldValue) {
						issues = append(issues, "unknown policy key: suppressions."+key)
					}
				}
				continue
			}
			key, value, ok := splitPolicyKeyValue(trimmed)
			if ok && currentSuppression != nil {
				if !setSuppressionField(currentSuppression, key, value) {
					issues = append(issues, "unknown policy key: suppressions."+key)
				}
			}
		}
	}
	flushSuppression()
	return policy, policyWarnings(path, policy.Strict, issues)
}

func appendProfileValues(profiles []model.ProfileID, value string, issues *[]string) []model.ProfileID {
	for _, raw := range splitPolicyValues(value) {
		profile, ok := ParseProfile(raw)
		if !ok {
			*issues = append(*issues, "unknown profile: "+raw)
			continue
		}
		profiles = append(profiles, profile)
	}
	return profiles
}

func appendRuleValues(policy *model.Policy, key string, value string, issues *[]string) {
	values := splitPolicyValues(value)
	switch key {
	case "enabled":
		policy.Rules.Enabled = append(policy.Rules.Enabled, values...)
	case "disabled":
		policy.Rules.Disabled = append(policy.Rules.Disabled, values...)
	case "severity":
		if value != "" {
			*issues = append(*issues, "policy rules.severity must be a mapping")
		}
	}
}

func appendSeverityOverride(policy *model.Policy, ruleID string, value string, issues *[]string) {
	severity, ok := parseSeverity(value)
	if !ok {
		*issues = append(*issues, "invalid severity override for "+ruleID+": "+value)
		return
	}
	policy.Rules.Severity[ruleID] = severity
}

func appendRegistryValues(policy *model.Policy, value string) {
	values := splitPolicyValues(value)
	if len(values) == 0 {
		return
	}
	if policy.Registries == nil {
		policy.Registries = &model.RegistryPolicy{Approved: []string{}}
	}
	policy.Registries.Approved = append(policy.Registries.Approved, values...)
}

func appendFirewallEndpointValues(policy *model.Policy, value string) {
	values := splitPolicyValues(value)
	if len(values) == 0 {
		return
	}
	if policy.PackageFirewall == nil {
		policy.PackageFirewall = &model.PackageFirewallPolicy{Endpoints: []string{}}
	}
	policy.PackageFirewall.Endpoints = append(policy.PackageFirewall.Endpoints, values...)
}

func setDefaultCooldownDays(policy *model.Policy, value string, issues *[]string) {
	days, err := strconv.Atoi(unquotePolicyValue(value))
	if err != nil || days < 0 {
		*issues = append(*issues, "invalid package_firewall.default_cooldown_days: "+value)
		return
	}
	if policy.PackageFirewall == nil {
		policy.PackageFirewall = &model.PackageFirewallPolicy{Endpoints: []string{}}
	}
	policy.PackageFirewall.DefaultCooldownDays = days
}

func setSuppressionField(suppression *model.Suppression, key string, value string) bool {
	value = unquotePolicyValue(value)
	switch key {
	case "rule_id":
		suppression.RuleID = value
	case "path":
		suppression.Path = filepath.ToSlash(value)
	case "reason":
		suppression.Reason = value
	default:
		return false
	}
	return true
}

func ParseProfile(value string) (model.ProfileID, bool) {
	switch model.ProfileID(value) {
	case model.ProfileBaseline, model.ProfileStrict, model.ProfileSocketFirewall, model.ProfileVeracodePackageFirewall, model.ProfilePrivateRegistry:
		return model.ProfileID(value), true
	default:
		return "", false
	}
}

func parseSeverity(value string) (model.Severity, bool) {
	value = unquotePolicyValue(value)
	switch model.Severity(value) {
	case model.SeverityInfo, model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical:
		return model.Severity(value), true
	default:
		return "", false
	}
}

func parsePolicyBool(value string) (bool, bool) {
	switch strings.ToLower(unquotePolicyValue(value)) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func policyWarnings(path string, strict bool, issues []string) []model.Warning {
	warnings := make([]model.Warning, 0, len(issues))
	for _, issue := range issues {
		message := issue
		if strict {
			message = "policy schema error: " + message
		}
		warnings = append(warnings, model.Warning{Path: path, Message: message})
	}
	return warnings
}

func stripPolicyComment(line string) string {
	inQuote := byte(0)
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'', '"':
			if inQuote == 0 {
				inQuote = line[i]
			} else if inQuote == line[i] {
				inQuote = 0
			}
		case '#':
			if inQuote == 0 {
				return line[:i]
			}
		}
	}
	return line
}

func leadingSpaces(line string) int {
	count := 0
	for _, r := range line {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

func listItem(value string) (string, bool) {
	if !strings.HasPrefix(value, "-") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "-")), true
}

func splitPolicyKeyValue(line string) (string, string, bool) {
	index := strings.Index(line, ":")
	if index < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:index]), strings.TrimSpace(line[index+1:]), true
}

func splitPolicyValues(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return []string{}
	}
	value = strings.Trim(value, "[]")
	parts := strings.Split(value, ",")
	values := []string{}
	for _, part := range parts {
		item := unquotePolicyValue(part)
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

func unquotePolicyValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}
