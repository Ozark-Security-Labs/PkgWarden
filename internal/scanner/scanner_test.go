package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

func TestScanExistingDirectory(t *testing.T) {
	report, err := Scan("../../fixtures/empty-repo")

	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if report.SchemaVersion == "" {
		t.Fatal("SchemaVersion is empty")
	}
	if report.Target != "../../fixtures/empty-repo" {
		t.Fatalf("Target = %q, want fixture path", report.Target)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("Findings len = %d, want 0", len(report.Findings))
	}
	if len(report.Warnings) != 0 {
		t.Fatalf("Warnings len = %d, want 0", len(report.Warnings))
	}
	if len(report.Inventory.Manifests) != 0 {
		t.Fatalf("Inventory.Manifests len = %d, want 0", len(report.Inventory.Manifests))
	}
	if len(report.Rules) == 0 {
		t.Fatal("Rules is empty")
	}
	if !ruleEnabled(report.Rules, "PW-R001") {
		t.Fatal("PW-R001 is not enabled by baseline profile")
	}
	if len(report.Profiles) == 0 {
		t.Fatal("Profiles is empty")
	}
	if len(report.Policy.Rules.Enabled) != 0 {
		t.Fatalf("Policy.Rules.Enabled len = %d, want 0", len(report.Policy.Rules.Enabled))
	}
}

func TestScanStrictProfileChangesEnabledRules(t *testing.T) {
	report, err := ScanWithOptions("../../fixtures/empty-repo", Options{Profile: "strict"})

	if err != nil {
		t.Fatalf("ScanWithOptions returned error: %v", err)
	}
	if !ruleEnabled(report.Rules, "PW-R000") {
		t.Fatal("PW-R000 is not enabled by strict profile")
	}
	if !ruleEnabled(report.Rules, "PW-R001") {
		t.Fatal("PW-R001 is not enabled by strict profile")
	}
}

func TestScanMissingTarget(t *testing.T) {
	_, err := Scan("../../fixtures/missing-repo")

	if err == nil {
		t.Fatal("Scan returned nil error for missing target")
	}
}

func TestScanInventoryMonorepo(t *testing.T) {
	report, err := Scan("../../fixtures/inventory-monorepo")

	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	assertInventoryPath(t, report.Inventory.Manifests, "package.json", "node", "npm")
	assertInventoryPath(t, report.Inventory.Manifests, "apps/api/go.mod", "go", "go")
	assertInventoryPath(t, report.Inventory.Manifests, "services/worker/pyproject.toml", "python", "python")
	assertInventoryPath(t, report.Inventory.Manifests, "services/worker/requirements-dev.txt", "python", "pip")
	assertInventoryPath(t, report.Inventory.Lockfiles, "package-lock.json", "node", "npm")
	assertInventoryPath(t, report.Inventory.Lockfiles, "apps/api/go.sum", "go", "go")
	assertInventoryPath(t, report.Inventory.Lockfiles, "services/worker/poetry.lock", "python", "poetry")
	assertInventoryPath(t, report.Inventory.PackageManagerConfigFiles, ".npmrc", "node", "npm")
	assertInventoryPath(t, report.Inventory.PackageManagerConfigFiles, "services/worker/poetry.toml", "python", "poetry")
	assertInventoryPath(t, report.Inventory.CIWorkflows, ".github/workflows/ci.yml", "", "")
	assertInventoryPath(t, report.Inventory.DependencyBots, ".github/dependabot.yml", "", "")

	assertSummary(t, report.Inventory.Ecosystems, "go")
	assertSummary(t, report.Inventory.Ecosystems, "node")
	assertSummary(t, report.Inventory.Ecosystems, "python")
	assertSummary(t, report.Inventory.PackageManagers, "go")
	assertSummary(t, report.Inventory.PackageManagers, "npm")
	assertSummary(t, report.Inventory.PackageManagers, "poetry")

	assertInventoryPathAbsent(t, report.Inventory.Manifests, "node_modules/ignored/package.json")
	assertInventoryPathAbsent(t, report.Inventory.Manifests, "vendor/ignored/go.mod")
	assertInventoryPathAbsent(t, report.Inventory.Lockfiles, "dist/package-lock.json")
	assertInventoryPathAbsent(t, report.Inventory.Manifests, ".venv/pyproject.toml")
}

func TestScanWarnsOnUnreadableWalkEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod permission behavior differs on windows")
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	if err := os.WriteFile(filepath.Join(locked, "package-lock.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write locked file: %v", err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatalf("chmod locked: %v", err)
	}
	defer os.Chmod(locked, 0o755)

	report, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(report.Warnings) == 0 {
		t.Fatal("Warnings len = 0, want warning for unreadable directory")
	}
	assertInventoryPath(t, report.Inventory.Manifests, "package.json", "node", "npm")
	assertInventoryPathAbsent(t, report.Inventory.Lockfiles, "locked/package-lock.json")
}

func TestScanReportsMissingLockfileFinding(t *testing.T) {
	report, err := Scan("../../fixtures/rules-missing-lockfile")

	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("Findings len = %d, want 1", len(report.Findings))
	}
	finding := report.Findings[0]
	if finding.RuleID != "PW-R001" {
		t.Fatalf("RuleID = %q, want PW-R001", finding.RuleID)
	}
	if finding.Category == "" || finding.Severity == "" || finding.Recommendation == "" {
		t.Fatalf("finding missing normalized fields: %#v", finding)
	}
	if len(finding.Locations) == 0 || finding.Locations[0].Path != "package.json" {
		t.Fatalf("finding locations = %#v, want package.json", finding.Locations)
	}
}

func TestScanPolicySuppressesFinding(t *testing.T) {
	report, err := Scan("../../fixtures/rules-policy-suppressed")

	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("Findings len = %d, want 0", len(report.Findings))
	}
	if len(report.SuppressedFindings) != 1 {
		t.Fatalf("SuppressedFindings len = %d, want 1", len(report.SuppressedFindings))
	}
}

func TestScanPolicyOverridesRuleSeverity(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".pkgwarden.yml"), []byte("rules:\n  severity:\n    PW-R001: high\n"), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	report, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("Findings len = %d, want 1", len(report.Findings))
	}
	if report.Findings[0].Severity != model.SeverityHigh {
		t.Fatalf("finding severity = %q, want high", report.Findings[0].Severity)
	}
	if got := ruleEnabledSeverity(report.Rules, "PW-R001"); got != model.SeverityHigh {
		t.Fatalf("PW-R001 rule severity = %q, want high", got)
	}
}

func TestScanInlineSuppressesFinding(t *testing.T) {
	report, err := Scan("../../fixtures/rules-inline-suppressed")

	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("Findings len = %d, want 0", len(report.Findings))
	}
	if len(report.SuppressedFindings) != 1 {
		t.Fatalf("SuppressedFindings len = %d, want 1", len(report.SuppressedFindings))
	}
}

func assertInventoryPath(t *testing.T, items []model.InventoryItem, path string, ecosystem string, packageManager string) {
	t.Helper()
	for _, item := range items {
		if len(item.Locations) == 0 {
			continue
		}
		if item.Locations[0].Path == path {
			if item.Ecosystem != ecosystem {
				t.Fatalf("%s ecosystem = %q, want %q", path, item.Ecosystem, ecosystem)
			}
			if item.PackageManager != packageManager {
				t.Fatalf("%s package manager = %q, want %q", path, item.PackageManager, packageManager)
			}
			return
		}
	}
	t.Fatalf("inventory path %q not found in %#v", path, items)
}

func assertInventoryPathAbsent(t *testing.T, items []model.InventoryItem, path string) {
	t.Helper()
	for _, item := range items {
		for _, location := range item.Locations {
			if location.Path == path {
				t.Fatalf("inventory path %q unexpectedly found", path)
			}
		}
	}
}

func assertSummary(t *testing.T, items []model.InventoryItem, name string) {
	t.Helper()
	for _, item := range items {
		if item.Name == name {
			if len(item.Locations) == 0 {
				t.Fatalf("summary %q has no locations", name)
			}
			return
		}
	}
	t.Fatalf("summary %q not found in %#v", name, items)
}

func ruleEnabled(rules []model.Rule, id string) bool {
	for _, rule := range rules {
		if rule.ID == id {
			return rule.Enabled
		}
	}
	return false
}

func ruleEnabledSeverity(rules []model.Rule, id string) model.Severity {
	for _, rule := range rules {
		if rule.ID == id {
			return rule.Severity
		}
	}
	return ""
}
