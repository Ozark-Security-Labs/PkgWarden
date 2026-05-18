package reporting

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

func TestWriteHuman(t *testing.T) {
	var out bytes.Buffer
	report := emptyReport("fixtures/empty-repo")

	if err := WriteHuman(&out, report); err != nil {
		t.Fatalf("WriteHuman returned error: %v", err)
	}

	want := "PkgWarden scan complete\nTarget: fixtures/empty-repo\nFindings: 0\nSuppressed: 0\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestWriteJSON(t *testing.T) {
	var out bytes.Buffer
	report := emptyReport("fixtures/empty-repo")

	if err := WriteJSON(&out, report); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	if !json.Valid(out.Bytes()) {
		t.Fatalf("output is not valid JSON: %q", out.String())
	}
	if !strings.Contains(out.String(), `"findings": []`) {
		t.Fatalf("output = %q, want empty findings array", out.String())
	}
	for _, field := range []string{`"inventory": {`, `"warnings": []`, `"suppressed_findings": []`, `"rules": []`, `"profiles": [`, `"policy": {`} {
		if !strings.Contains(out.String(), field) {
			t.Fatalf("output = %q, want field %s", out.String(), field)
		}
	}
}

func TestWriteHumanWithWarnings(t *testing.T) {
	var out bytes.Buffer
	report := emptyReport("fixtures/warnings")
	report.Warnings = []model.Warning{
		{Path: "locked", Message: "permission denied"},
	}

	if err := WriteHuman(&out, report); err != nil {
		t.Fatalf("WriteHuman returned error: %v", err)
	}

	want := "PkgWarden scan complete\nTarget: fixtures/warnings\nFindings: 0\nSuppressed: 0\nWarnings: 1\nWarning: locked: permission denied\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestWriteHumanGroupsFindings(t *testing.T) {
	var out bytes.Buffer
	report := emptyReport("fixtures/grouped")
	report.Inventory.Manifests = []model.InventoryItem{
		{
			Name:      "package.json",
			Ecosystem: "node",
			Locations: []model.Location{
				{Path: "package.json"},
			},
		},
		{
			Name:      "go.mod",
			Ecosystem: "go",
			Locations: []model.Location{
				{Path: "go.mod"},
			},
		},
	}
	report.Findings = []model.Finding{
		{
			RuleID:         "PW-R002",
			Title:          "Registry token is committed",
			Severity:       model.SeverityHigh,
			Category:       "registry",
			Locations:      []model.Location{{Path: "package.json", StartLine: 4}},
			Evidence:       []model.Evidence{{Description: "_authToken=npm_secret_value was detected", Locations: []model.Location{{Path: "package.json", StartLine: 4}}}},
			Recommendation: "Remove the committed token.",
		},
		{
			RuleID:         "PW-R001",
			Title:          "Package manifest has no matching lockfile",
			Severity:       model.SeverityMedium,
			Category:       "lockfile",
			Locations:      []model.Location{{Path: "go.mod"}},
			Evidence:       []model.Evidence{{Description: "Manifest go.mod was detected without a same-directory lockfile.", Locations: []model.Location{{Path: "go.mod"}}}},
			Recommendation: "Commit go.sum.",
		},
		{
			RuleID:         "PW-R003",
			Title:          "Registry is not pinned",
			Severity:       model.SeverityMedium,
			Category:       "registry",
			Locations:      []model.Location{{Path: "package.json"}},
			Evidence:       []model.Evidence{{Description: "Registry configuration was detected.", Locations: []model.Location{{Path: "package.json"}}}},
			Recommendation: "Pin the registry configuration.",
		},
	}
	report.SuppressedFindings = []model.Finding{{RuleID: "PW-R004"}}

	if err := WriteHuman(&out, report); err != nil {
		t.Fatalf("WriteHuman returned error: %v", err)
	}

	want := strings.Join([]string{
		"PkgWarden scan complete",
		"Target: fixtures/grouped",
		"Findings: 3",
		"Suppressed: 1",
		"",
		"High severity (1)",
		"  node / registry (1)",
		"    - PW-R002: Registry token is committed",
		"      Location: package.json:4",
		"      Evidence: _authToken=[REDACTED] was detected",
		"      Recommendation: Remove the committed token.",
		"",
		"Medium severity (2)",
		"  go / lockfile (1)",
		"    - PW-R001: Package manifest has no matching lockfile",
		"      Location: go.mod",
		"      Evidence: Manifest go.mod was detected without a same-directory lockfile.",
		"      Recommendation: Commit go.sum.",
		"  node / registry (1)",
		"    - PW-R003: Registry is not pinned",
		"      Location: package.json",
		"      Evidence: Registry configuration was detected.",
		"      Recommendation: Pin the registry configuration.",
		"",
	}, "\n")
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestWriteJSONRedactsEvidence(t *testing.T) {
	var out bytes.Buffer
	report := emptyReport("fixtures/redacted")
	report.Findings = []model.Finding{
		{
			RuleID:   "PW-R002",
			Title:    "Registry token is committed",
			Severity: model.SeverityHigh,
			Category: "registry",
			Evidence: []model.Evidence{
				{Description: "Found _authToken=npm_secret_value in package manager config."},
			},
		},
	}
	report.SuppressedFindings = []model.Finding{
		{
			RuleID:   "PW-R002",
			Title:    "Registry token is suppressed",
			Severity: model.SeverityHigh,
			Category: "registry",
			Evidence: []model.Evidence{
				{Description: "Suppressed token: npm_suppressed_secret"},
			},
		},
	}

	if err := WriteJSON(&out, report); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	if strings.Contains(out.String(), "npm_secret_value") || strings.Contains(out.String(), "npm_suppressed_secret") {
		t.Fatalf("output contains raw token: %s", out.String())
	}
	for _, want := range []string{`_authToken=[REDACTED]`, `Suppressed token: [REDACTED]`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output = %q, want redacted evidence %s", out.String(), want)
		}
	}
}

func TestReportFormatsUseSharedRedaction(t *testing.T) {
	report := emptyReport("fixtures/redacted")
	report.Inventory.Manifests = []model.InventoryItem{
		{Name: "package.json", Ecosystem: "node", Locations: []model.Location{{Path: "package.json"}}},
	}
	report.Findings = []model.Finding{
		{
			RuleID:         "PW-R010",
			Title:          "Credentials in registry URL",
			Severity:       model.SeverityHigh,
			Category:       "secrets",
			Locations:      []model.Location{{Path: "package.json"}},
			Evidence:       []model.Evidence{{Description: "registry https://user:pass123@registry.example and Authorization: Bearer abc.def.ghi"}},
			Recommendation: "Remove credentials from package-manager configuration.",
		},
	}

	var human bytes.Buffer
	if err := WriteHuman(&human, report); err != nil {
		t.Fatalf("WriteHuman returned error: %v", err)
	}
	var jsonOut bytes.Buffer
	if err := WriteJSON(&jsonOut, report); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	for label, output := range map[string]string{"human": human.String(), "json": jsonOut.String()} {
		for _, raw := range []string{"user", "pass123", "abc.def.ghi"} {
			if strings.Contains(output, raw) {
				t.Fatalf("%s output contains raw secret %q: %s", label, raw, output)
			}
		}
		for _, want := range []string{"https://REDACTED@registry.example", "Bearer [REDACTED]"} {
			if !strings.Contains(output, want) {
				t.Fatalf("%s output = %q, want redacted context %q", label, output, want)
			}
		}
	}
}

func TestWriteJSONRedactsPolicyEndpoints(t *testing.T) {
	var out bytes.Buffer
	report := emptyReport("fixtures/redacted-policy")
	report.Policy.Registries = &model.RegistryPolicy{
		Approved: []string{"https://registry-user:registry-token@registry.example/npm"},
	}
	report.Policy.PackageFirewall = &model.PackageFirewallPolicy{
		Endpoints: []string{"https://firewall-user:firewall-token@firewall.example/api"},
	}

	if err := WriteJSON(&out, report); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	for _, raw := range []string{"registry-user", "registry-token", "firewall-user", "firewall-token"} {
		if strings.Contains(out.String(), raw) {
			t.Fatalf("output contains raw policy credential %q: %s", raw, out.String())
		}
	}
	for _, want := range []string{"https://REDACTED@registry.example/npm", "https://REDACTED@firewall.example/api"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output = %q, want redacted policy endpoint %q", out.String(), want)
		}
	}
	if report.Policy.Registries.Approved[0] != "https://registry-user:registry-token@registry.example/npm" {
		t.Fatalf("original registry endpoint mutated: %#v", report.Policy.Registries.Approved)
	}
	if report.Policy.PackageFirewall.Endpoints[0] != "https://firewall-user:firewall-token@firewall.example/api" {
		t.Fatalf("original firewall endpoint mutated: %#v", report.Policy.PackageFirewall.Endpoints)
	}
}

func TestWriteJSONRedactsWarningsAndPolicyStrings(t *testing.T) {
	var out bytes.Buffer
	report := emptyReport("fixtures/redacted-policy")
	report.Warnings = []model.Warning{
		{Path: "config/npm_publish.yml", Message: "policy warning token=npm_abcdefghijklmnopqrstuvwxyz1234567890"},
	}
	report.Policy.Rules.Enabled = []string{"npm_enabled_rule"}
	report.Policy.Rules.Disabled = []string{"npm_disabled_rule"}
	report.Policy.Rules.Severity = map[string]model.Severity{
		"npm_severity_rule": model.SeverityHigh,
	}
	report.Policy.Suppressions = []model.Suppression{
		{
			RuleID: "npm_suppression_rule",
			Path:   "config/npm_suppression.yml",
			Reason: "accepted risk password=package-secret",
		},
	}

	if err := WriteJSON(&out, report); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	for _, raw := range []string{
		"npm_abcdefghijklmnopqrstuvwxyz1234567890",
		"package-secret",
	} {
		if strings.Contains(out.String(), raw) {
			t.Fatalf("output contains raw policy string %q: %s", raw, out.String())
		}
	}
	for _, want := range []string{
		`config/npm_publish.yml`,
		`policy warning token=[REDACTED]`,
		`"npm_enabled_rule"`,
		`"npm_disabled_rule"`,
		`"npm_severity_rule"`,
		`"npm_suppression_rule"`,
		`config/npm_suppression.yml`,
		`accepted risk password=[REDACTED]`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output = %q, want redacted context %q", out.String(), want)
		}
	}
	if report.Warnings[0].Path != "config/npm_publish.yml" {
		t.Fatalf("original warning path mutated: %#v", report.Warnings)
	}
	if report.Policy.Rules.Enabled[0] != "npm_enabled_rule" {
		t.Fatalf("original enabled rules mutated: %#v", report.Policy.Rules.Enabled)
	}
	if _, ok := report.Policy.Rules.Severity["npm_severity_rule"]; !ok {
		t.Fatalf("original severity overrides mutated: %#v", report.Policy.Rules.Severity)
	}
	if report.Policy.Suppressions[0].Reason != "accepted risk password=package-secret" {
		t.Fatalf("original suppressions mutated: %#v", report.Policy.Suppressions)
	}
}

func TestWriteHumanRedactsWarnings(t *testing.T) {
	var out bytes.Buffer
	report := emptyReport("fixtures/redacted-warnings")
	report.Warnings = []model.Warning{
		{Path: "config/npm_publish.yml", Message: "policy warning token=npm_abcdefghijklmnopqrstuvwxyz1234567890"},
	}

	if err := WriteHuman(&out, report); err != nil {
		t.Fatalf("WriteHuman returned error: %v", err)
	}

	for _, raw := range []string{"npm_abcdefghijklmnopqrstuvwxyz1234567890"} {
		if strings.Contains(out.String(), raw) {
			t.Fatalf("human output contains raw warning string %q: %s", raw, out.String())
		}
	}
	for _, want := range []string{"Warning: config/npm_publish.yml: policy warning token=[REDACTED]"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("human output = %q, want redacted warning %q", out.String(), want)
		}
	}
	if report.Warnings[0].Message != "policy warning token=npm_abcdefghijklmnopqrstuvwxyz1234567890" {
		t.Fatalf("original warning mutated: %#v", report.Warnings)
	}
}

func emptyReport(target string) model.Report {
	return model.Report{
		SchemaVersion:      "0.1.0",
		Target:             target,
		Inventory:          model.EmptyInventory(),
		Warnings:           []model.Warning{},
		Findings:           []model.Finding{},
		SuppressedFindings: []model.Finding{},
		Rules:              []model.Rule{},
		Profiles:           model.DefaultProfiles(),
		Policy:             model.EmptyPolicy(),
	}
}
