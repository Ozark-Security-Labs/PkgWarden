package rules

import (
	"testing"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

func TestRegisteredRulesAreSorted(t *testing.T) {
	registered := Registered()

	for i := 1; i < len(registered); i++ {
		if registered[i-1].Metadata().ID > registered[i].Metadata().ID {
			t.Fatalf("rules are not sorted: %s before %s", registered[i-1].Metadata().ID, registered[i].Metadata().ID)
		}
	}
}

func TestExecuteSelectsRulesByProfile(t *testing.T) {
	result := Execute(Context{Inventory: model.EmptyInventory()}, model.ProfileBaseline, model.EmptyPolicy())

	if ruleEnabled(result.Rules, "PW-R000") {
		t.Fatal("PW-R000 enabled for baseline, want strict only")
	}
	if !ruleEnabled(result.Rules, "PW-R001") {
		t.Fatal("PW-R001 disabled for baseline, want enabled")
	}

	strict := Execute(Context{Inventory: model.EmptyInventory()}, model.ProfileStrict, model.EmptyPolicy())
	if !ruleEnabled(strict.Rules, "PW-R000") {
		t.Fatal("PW-R000 disabled for strict, want enabled")
	}
}

func TestExecuteAppliesPolicyOverrides(t *testing.T) {
	policy := model.EmptyPolicy()
	policy.Rules.Disabled = []string{"PW-R001"}
	policy.Rules.Enabled = []string{"PW-R000"}

	result := Execute(Context{Inventory: model.EmptyInventory()}, model.ProfileBaseline, policy)

	if !ruleEnabled(result.Rules, "PW-R000") {
		t.Fatal("PW-R000 disabled, want explicitly enabled")
	}
	if ruleEnabled(result.Rules, "PW-R001") {
		t.Fatal("PW-R001 enabled, want explicitly disabled")
	}
}

func TestExecuteAppliesSeverityOverrides(t *testing.T) {
	policy := model.EmptyPolicy()
	policy.Rules.Severity["PW-R001"] = model.SeverityHigh
	inventory := model.EmptyInventory()
	inventory.Manifests = []model.InventoryItem{
		{
			Name:           "package.json",
			PackageManager: "npm",
			Locations:      []model.Location{{Path: "package.json"}},
		},
	}

	result := Execute(Context{Inventory: inventory}, model.ProfileBaseline, policy)

	if got := ruleSeverity(result.Rules, "PW-R001"); got != model.SeverityHigh {
		t.Fatalf("PW-R001 rule severity = %q, want high", got)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings len = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].Severity != model.SeverityHigh {
		t.Fatalf("finding severity = %q, want high", result.Findings[0].Severity)
	}
}

func TestExecuteDeduplicatesFindings(t *testing.T) {
	finding := model.Finding{
		RuleID:    "PW-R001",
		Title:     "duplicate",
		Locations: []model.Location{{Path: "package.json"}},
		Evidence:  []model.Evidence{{Description: "same"}},
	}
	deduped := dedupeFindings([]model.Finding{finding, finding})

	if len(deduped) != 1 {
		t.Fatalf("deduped len = %d, want 1", len(deduped))
	}
}

func TestMissingLockfileRuleFindsPackageJSONWithoutLockfile(t *testing.T) {
	inventory := model.EmptyInventory()
	inventory.Manifests = []model.InventoryItem{
		{
			Name:           "package.json",
			PackageManager: "npm",
			Locations:      []model.Location{{Path: "package.json"}},
		},
	}
	result := Execute(Context{Inventory: inventory}, model.ProfileBaseline, model.EmptyPolicy())

	if len(result.Findings) != 1 {
		t.Fatalf("Findings len = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].RuleID != "PW-R001" {
		t.Fatalf("RuleID = %q, want PW-R001", result.Findings[0].RuleID)
	}
}

func ruleEnabled(rules []model.Rule, id string) bool {
	for _, rule := range rules {
		if rule.ID == id {
			return rule.Enabled
		}
	}
	return false
}

func ruleSeverity(rules []model.Rule, id string) model.Severity {
	for _, rule := range rules {
		if rule.ID == id {
			return rule.Severity
		}
	}
	return ""
}
