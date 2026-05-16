package rules

import (
	"sort"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

type Rule interface {
	Metadata() model.Rule
	Evaluate(Context) []model.Finding
}

type Context struct {
	Target    string
	Inventory model.Inventory
}

type Result struct {
	Findings           []model.Finding
	SuppressedFindings []model.Finding
	Rules              []model.Rule
}

func Execute(ctx Context, profile model.ProfileID, policy model.Policy) Result {
	registered := Registered()
	enabled := enabledRuleIDs(registered, profile, policy)

	activeRules := make([]model.Rule, 0, len(registered))
	findings := []model.Finding{}
	for _, rule := range registered {
		metadata := rule.Metadata()
		metadata.Enabled = enabled[metadata.ID]
		activeRules = append(activeRules, metadata)
		if !metadata.Enabled {
			continue
		}
		findings = append(findings, rule.Evaluate(ctx)...)
	}

	findings = dedupeFindings(findings)
	active, suppressed := suppressFindings(ctx.Target, findings, policy.Suppressions)
	return Result{
		Findings:           active,
		SuppressedFindings: suppressed,
		Rules:              activeRules,
	}
}

func enabledRuleIDs(registered []Rule, profile model.ProfileID, policy model.Policy) map[string]bool {
	enabled := map[string]bool{}
	for _, rule := range registered {
		metadata := rule.Metadata()
		if appliesToProfile(metadata, profile) {
			enabled[metadata.ID] = true
		}
	}
	for _, id := range policy.Rules.Disabled {
		enabled[id] = false
	}
	for _, id := range policy.Rules.Enabled {
		enabled[id] = true
	}
	return enabled
}

func appliesToProfile(rule model.Rule, profile model.ProfileID) bool {
	for _, candidate := range rule.Profiles {
		if candidate == profile {
			return true
		}
	}
	return false
}

func dedupeFindings(findings []model.Finding) []model.Finding {
	seen := map[string]struct{}{}
	deduped := []model.Finding{}
	for _, finding := range findings {
		key := findingKey(finding)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, finding)
	}
	sort.Slice(deduped, func(i, j int) bool {
		return findingKey(deduped[i]) < findingKey(deduped[j])
	})
	return deduped
}

func findingKey(finding model.Finding) string {
	location := ""
	if len(finding.Locations) > 0 {
		first := finding.Locations[0]
		location = first.Path
		if first.StartLine > 0 {
			location += ":" + itoa(first.StartLine)
		}
	}
	evidence := ""
	if len(finding.Evidence) > 0 {
		evidence = finding.Evidence[0].Description
	}
	return finding.RuleID + "|" + location + "|" + finding.Title + "|" + evidence
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}
