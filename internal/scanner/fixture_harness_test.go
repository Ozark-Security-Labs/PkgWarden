package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

type fixtureCase struct {
	name                string
	profile             model.ProfileID
	policyPath          string
	golden              string
	wantEnabledRules    []string
	wantFindingRules    []string
	wantSuppressedRules []string
}

func TestFixtureGoldenOutputs(t *testing.T) {
	cases := []fixtureCase{
		{name: "empty-repo", golden: "empty-repo.json", wantEnabledRules: []string{"PW-R001"}},
		{name: "single-package-locked", golden: "single-package-locked.json", wantEnabledRules: []string{"PW-R001"}},
		{name: "rules-missing-lockfile", golden: "rules-missing-lockfile.json", wantEnabledRules: []string{"PW-R001"}, wantFindingRules: []string{"PW-R001"}},
		{name: "rules-policy-suppressed", golden: "rules-policy-suppressed.json", wantEnabledRules: []string{"PW-R001"}, wantSuppressedRules: []string{"PW-R001"}},
		{name: "malformed-config", golden: "malformed-config.json", wantEnabledRules: []string{"PW-R001"}},
		{name: "mixed-ecosystem", profile: model.ProfileStrict, golden: "mixed-ecosystem-strict.json", wantEnabledRules: []string{"PW-R000", "PW-R001"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := runFixture(t, tc)
			got := marshalGolden(t, report)
			goldenPath := filepath.Join("..", "..", "fixtures", "golden", tc.golden)
			if os.Getenv("UPDATE_GOLDENS") == "1" {
				if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
					t.Fatalf("mkdir golden dir: %v", err)
				}
				if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
					t.Fatalf("write golden %s: %v", goldenPath, err)
				}
				return
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden %s: %v", goldenPath, err)
			}
			if string(want) != got {
				t.Fatalf("golden mismatch for %s; update %s after reviewing scanner output", tc.name, goldenPath)
			}
		})
	}
}

func TestFixtureHarnessRuleSubset(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "package.json", "{\n  \"name\": \"subset\"\n}\n")
	writeFixtureFile(t, root, "package-lock.json", "{\n  \"lockfileVersion\": 3\n}\n")
	writeFixtureFile(t, root, ".pkgwarden.yml", "profiles:\n  - strict\nrules:\n  disabled:\n    - PW-R001\n")

	report, err := ScanWithOptions(root, Options{})
	if err != nil {
		t.Fatalf("ScanWithOptions returned error: %v", err)
	}
	enabled := enabledRuleIDs(report.Rules)
	if !reflect.DeepEqual(enabled, []string{"PW-R000"}) {
		t.Fatalf("enabled rules = %#v, want PW-R000 only", enabled)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("Findings len = %d, want 0", len(report.Findings))
	}
}

func TestFixtureBuilderCreatesPackageExample(t *testing.T) {
	root := t.TempDir()
	writeNodePackageFixture(t, root, true)

	report, err := ScanWithOptions(root, Options{})
	if err != nil {
		t.Fatalf("ScanWithOptions returned error: %v", err)
	}
	if len(report.Inventory.Manifests) != 1 {
		t.Fatalf("manifests len = %d, want 1", len(report.Inventory.Manifests))
	}
	if len(report.Inventory.Lockfiles) != 1 {
		t.Fatalf("lockfiles len = %d, want 1", len(report.Inventory.Lockfiles))
	}
}

func runFixture(t *testing.T, tc fixtureCase) model.Report {
	t.Helper()
	root := filepath.Join("..", "..", "fixtures", tc.name)
	options := Options{Profile: tc.profile}
	if tc.policyPath != "" {
		options.PolicyPath = filepath.Join(root, tc.policyPath)
	}
	report, err := ScanWithOptions(root, options)
	if err != nil {
		t.Fatalf("ScanWithOptions returned error: %v", err)
	}
	report.Target = filepath.ToSlash(filepath.Join("fixtures", tc.name))
	assertRuleIDs(t, "enabled", enabledRuleIDs(report.Rules), tc.wantEnabledRules)
	assertRuleIDs(t, "finding", findingRuleIDs(report.Findings), tc.wantFindingRules)
	assertRuleIDs(t, "suppressed", findingRuleIDs(report.SuppressedFindings), tc.wantSuppressedRules)
	return report
}

func marshalGolden(t *testing.T, report model.Report) string {
	t.Helper()
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	return string(encoded) + "\n"
}

func enabledRuleIDs(rules []model.Rule) []string {
	ids := []string{}
	for _, rule := range rules {
		if rule.Enabled {
			ids = append(ids, rule.ID)
		}
	}
	slices.Sort(ids)
	return ids
}

func findingRuleIDs(findings []model.Finding) []string {
	ids := []string{}
	for _, finding := range findings {
		ids = append(ids, finding.RuleID)
	}
	slices.Sort(ids)
	return ids
}

func assertRuleIDs(t *testing.T, label string, got []string, want []string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s rule ids = %#v, want %#v", label, got, want)
	}
}

func writeNodePackageFixture(t *testing.T, root string, withLockfile bool) {
	t.Helper()
	writeFixtureFile(t, root, "package.json", "{\n  \"name\": \"fixture\"\n}\n")
	if withLockfile {
		writeFixtureFile(t, root, "package-lock.json", "{\n  \"lockfileVersion\": 3\n}\n")
	}
}

func writeFixtureFile(t *testing.T, root string, path string, content string) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(fullPath), err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", fullPath, err)
	}
}
