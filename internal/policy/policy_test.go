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

func TestLoadOptionalMissingPolicy(t *testing.T) {
	loaded, warnings := LoadOptional(t.TempDir(), "")

	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	if len(loaded.Profiles) != 0 {
		t.Fatalf("profiles = %#v, want empty", loaded.Profiles)
	}
}
