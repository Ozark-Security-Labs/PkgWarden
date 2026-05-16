package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

const DefaultFilename = ".pkgwarden.yml"

func Load(path string) (model.Policy, []model.Warning) {
	content, err := os.ReadFile(path)
	if err != nil {
		return model.EmptyPolicy(), []model.Warning{{Path: filepath.ToSlash(path), Message: err.Error()}}
	}
	policy := model.EmptyPolicy()
	warnings := []model.Warning{}

	parsed, parseWarnings := parsePolicyLines(filepath.ToSlash(filepath.Base(path)), content)
	warnings = append(warnings, parseWarnings...)
	if len(parsed.Profiles) > 0 {
		policy.Profiles = parsed.Profiles
	}
	policy.Rules = parsed.Rules
	policy.Suppressions = parsed.Suppressions
	return policy, warnings
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
	warnings := []model.Warning{}
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	section := ""
	ruleList := ""
	var currentSuppression *model.Suppression

	flushSuppression := func() {
		if currentSuppression == nil {
			return
		}
		if currentSuppression.RuleID != "" {
			policy.Suppressions = append(policy.Suppressions, *currentSuppression)
		} else {
			warnings = append(warnings, model.Warning{Path: path, Message: "policy suppression missing rule_id"})
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
			key, value, ok := splitPolicyKeyValue(trimmed)
			if !ok {
				warnings = append(warnings, model.Warning{Path: path, Message: "policy line is not key/value: " + trimmed})
				continue
			}
			section = key
			switch key {
			case "profiles":
				policy.Profiles = appendProfileValues(policy.Profiles, value, &warnings, path)
			case "rules", "suppressions":
			default:
				warnings = append(warnings, model.Warning{Path: path, Message: "unknown policy section: " + key})
			}
			continue
		}

		switch section {
		case "profiles":
			if value, ok := listItem(trimmed); ok {
				policy.Profiles = appendProfileValues(policy.Profiles, value, &warnings, path)
			}
		case "rules":
			key, value, ok := splitPolicyKeyValue(trimmed)
			if ok && (key == "enabled" || key == "disabled") {
				ruleList = key
				appendRuleValues(&policy, key, value)
				continue
			}
			if value, ok := listItem(trimmed); ok {
				appendRuleValues(&policy, ruleList, value)
			}
		case "suppressions":
			if value, ok := listItem(trimmed); ok {
				flushSuppression()
				currentSuppression = &model.Suppression{}
				if key, fieldValue, ok := splitPolicyKeyValue(value); ok {
					setSuppressionField(currentSuppression, key, fieldValue)
				}
				continue
			}
			key, value, ok := splitPolicyKeyValue(trimmed)
			if ok && currentSuppression != nil {
				setSuppressionField(currentSuppression, key, value)
			}
		}
	}
	flushSuppression()
	return policy, warnings
}

func appendProfileValues(profiles []model.ProfileID, value string, warnings *[]model.Warning, path string) []model.ProfileID {
	for _, raw := range splitPolicyValues(value) {
		profile, ok := ParseProfile(raw)
		if !ok {
			*warnings = append(*warnings, model.Warning{Path: path, Message: "unknown profile: " + raw})
			continue
		}
		profiles = append(profiles, profile)
	}
	return profiles
}

func appendRuleValues(policy *model.Policy, key string, value string) {
	values := splitPolicyValues(value)
	switch key {
	case "enabled":
		policy.Rules.Enabled = append(policy.Rules.Enabled, values...)
	case "disabled":
		policy.Rules.Disabled = append(policy.Rules.Disabled, values...)
	}
}

func setSuppressionField(suppression *model.Suppression, key string, value string) {
	value = unquotePolicyValue(value)
	switch key {
	case "rule_id":
		suppression.RuleID = value
	case "path":
		suppression.Path = filepath.ToSlash(value)
	case "reason":
		suppression.Reason = value
	}
}

func ParseProfile(value string) (model.ProfileID, bool) {
	switch model.ProfileID(value) {
	case model.ProfileBaseline, model.ProfileStrict, model.ProfileSocketFirewall, model.ProfileVeracodePackageFirewall, model.ProfilePrivateRegistry:
		return model.ProfileID(value), true
	default:
		return "", false
	}
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
