package scanner

import "testing"

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
	if len(report.Inventory.Manifests) != 0 {
		t.Fatalf("Inventory.Manifests len = %d, want 0", len(report.Inventory.Manifests))
	}
	if len(report.Rules) != 0 {
		t.Fatalf("Rules len = %d, want 0", len(report.Rules))
	}
	if len(report.Profiles) == 0 {
		t.Fatal("Profiles is empty")
	}
	if len(report.Policy.Rules.Enabled) != 0 {
		t.Fatalf("Policy.Rules.Enabled len = %d, want 0", len(report.Policy.Rules.Enabled))
	}
}

func TestScanMissingTarget(t *testing.T) {
	_, err := Scan("../../fixtures/missing-repo")

	if err == nil {
		t.Fatal("Scan returned nil error for missing target")
	}
}
