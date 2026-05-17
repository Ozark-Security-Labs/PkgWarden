package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

func TestLoadPolicy(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".pkgwarden.yml")
	content := []byte(`profiles:
  - strict
rules:
  enabled:
    - PW-R000
  disabled:
    - PW-R001
suppressions:
  - rule_id: PW-R001
    path: package.json
    reason: test
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	loaded, warnings := Load(path)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	if len(loaded.Profiles) != 1 || loaded.Profiles[0] != model.ProfileStrict {
		t.Fatalf("profiles = %#v, want strict", loaded.Profiles)
	}
	if len(loaded.Rules.Enabled) != 1 || loaded.Rules.Enabled[0] != "PW-R000" {
		t.Fatalf("enabled = %#v, want PW-R000", loaded.Rules.Enabled)
	}
	if len(loaded.Rules.Disabled) != 1 || loaded.Rules.Disabled[0] != "PW-R001" {
		t.Fatalf("disabled = %#v, want PW-R001", loaded.Rules.Disabled)
	}
	if len(loaded.Suppressions) != 1 || loaded.Suppressions[0].Path != "package.json" {
		t.Fatalf("suppressions = %#v, want package.json", loaded.Suppressions)
	}
}

func TestLoadGroupedPolicy(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".pkgwarden.yml")
	content := []byte(`strict: true
profiles:
  - strict
registries:
  approved:
    - https://registry.npmjs.org
package_firewall:
  endpoints:
    - https://firewall.example.local
  default_cooldown_days: 7
rules:
  enabled:
    - PW-R000
  severity:
    PW-R001: high
suppressions:
  - rule_id: PW-R001
    path: package.json
    reason: fixture suppression
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	loaded, warnings := Load(path)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	if !loaded.Strict {
		t.Fatal("Strict = false, want true")
	}
	if loaded.Registries == nil || len(loaded.Registries.Approved) != 1 || loaded.Registries.Approved[0] != "https://registry.npmjs.org" {
		t.Fatalf("Registries = %#v, want approved npm registry", loaded.Registries)
	}
	if loaded.PackageFirewall == nil || len(loaded.PackageFirewall.Endpoints) != 1 || loaded.PackageFirewall.Endpoints[0] != "https://firewall.example.local" {
		t.Fatalf("PackageFirewall = %#v, want endpoint", loaded.PackageFirewall)
	}
	if loaded.PackageFirewall.DefaultCooldownDays != 7 {
		t.Fatalf("DefaultCooldownDays = %d, want 7", loaded.PackageFirewall.DefaultCooldownDays)
	}
	if got := loaded.Rules.Severity["PW-R001"]; got != model.SeverityHigh {
		t.Fatalf("severity override = %q, want high", got)
	}
}

func TestLoadPolicyUnknownKeysWarnByStrictness(t *testing.T) {
	root := t.TempDir()

	defaultPath := filepath.Join(root, "default.yml")
	if err := os.WriteFile(defaultPath, []byte("unknown: value\n"), 0o644); err != nil {
		t.Fatalf("write default policy: %v", err)
	}
	_, defaultWarnings := Load(defaultPath)
	if len(defaultWarnings) != 1 || defaultWarnings[0].Message != "unknown policy section: unknown" {
		t.Fatalf("default warnings = %#v, want unknown section warning", defaultWarnings)
	}

	strictPath := filepath.Join(root, "strict.yml")
	if err := os.WriteFile(strictPath, []byte("strict: true\nunknown: value\n"), 0o644); err != nil {
		t.Fatalf("write strict policy: %v", err)
	}
	_, strictWarnings := Load(strictPath)
	if len(strictWarnings) != 1 || strictWarnings[0].Message != "policy schema error: unknown policy section: unknown" {
		t.Fatalf("strict warnings = %#v, want schema error warning", strictWarnings)
	}
}

func TestLoadPolicyRequiresSuppressionReason(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".pkgwarden.yml")
	content := []byte(`suppressions:
  - rule_id: PW-R001
    path: package.json
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	loaded, warnings := Load(path)
	if len(loaded.Suppressions) != 0 {
		t.Fatalf("Suppressions = %#v, want missing-reason suppression ignored", loaded.Suppressions)
	}
	if len(warnings) != 1 || warnings[0].Message != "policy suppression missing reason" {
		t.Fatalf("warnings = %#v, want missing reason warning", warnings)
	}
}

func TestLoadPolicyInvalidSeverityOverrideWarns(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".pkgwarden.yml")
	content := []byte(`rules:
  severity:
    PW-R001: urgent
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	loaded, warnings := Load(path)
	if len(loaded.Rules.Severity) != 0 {
		t.Fatalf("Rules.Severity = %#v, want no invalid override", loaded.Rules.Severity)
	}
	if len(warnings) != 1 || warnings[0].Message != "invalid severity override for PW-R001: urgent" {
		t.Fatalf("warnings = %#v, want invalid severity warning", warnings)
	}
}

func TestLoadOptionalMissingPolicy(t *testing.T) {
	loaded, warnings := LoadOptional(t.TempDir(), "")

	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	if len(loaded.Profiles) != 0 {
		t.Fatalf("profiles = %#v, want empty", loaded.Profiles)
	}
}
