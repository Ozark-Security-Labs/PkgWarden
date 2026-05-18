package rules

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

const inlineSuppressionPrefix = "pkgwarden:ignore"

func suppressFindings(target string, findings []model.Finding, suppressions []model.Suppression) ([]model.Finding, []model.Finding) {
	active := []model.Finding{}
	suppressed := []model.Finding{}
	for _, finding := range findings {
		if isSuppressedByPolicy(finding, suppressions) || isSuppressedInline(target, finding) {
			suppressed = append(suppressed, finding)
			continue
		}
		active = append(active, finding)
	}
	return active, suppressed
}

func isSuppressedByPolicy(finding model.Finding, suppressions []model.Suppression) bool {
	for _, suppression := range suppressions {
		if suppression.RuleID != finding.RuleID {
			continue
		}
		if suppression.Path == "" {
			return true
		}
		for _, location := range finding.Locations {
			if location.Path == suppression.Path {
				return true
			}
		}
	}
	return false
}

func isSuppressedInline(target string, finding model.Finding) bool {
	for _, location := range finding.Locations {
		content, err := os.ReadFile(filepath.Join(target, filepath.FromSlash(location.Path)))
		if err != nil {
			continue
		}
		if inlineSuppressionMatches(string(content), finding.RuleID, location.StartLine) {
			return true
		}
	}
	return false
}

func inlineSuppressionMatches(content string, ruleID string, startLine int) bool {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	if startLine > 0 {
		if lineHasSuppression(lines, startLine, ruleID) {
			return true
		}
		if startLine > 1 && lineHasSuppression(lines, startLine-1, ruleID) {
			return true
		}
		return false
	}
	limit := 10
	if len(lines) < limit {
		limit = len(lines)
	}
	for i := 1; i <= limit; i++ {
		if lineHasSuppression(lines, i, ruleID) {
			return true
		}
	}
	return false
}

func lineHasSuppression(lines []string, oneBasedLine int, ruleID string) bool {
	if oneBasedLine <= 0 || oneBasedLine > len(lines) {
		return false
	}
	line := lines[oneBasedLine-1]
	index := strings.Index(line, inlineSuppressionPrefix)
	if index < 0 {
		return false
	}
	fields := strings.Fields(line[index:])
	return len(fields) >= 3 && fields[0] == inlineSuppressionPrefix && fields[1] == ruleID
}
