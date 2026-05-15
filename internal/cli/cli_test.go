package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

func TestScanEmptyRepoHuman(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"scan", "../../fixtures/empty-repo"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Findings: 0") {
		t.Fatalf("stdout = %q, want findings count", stdout.String())
	}
}

func TestScanIgnoresLeadingSeparator(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"--", "scan", "../../fixtures/empty-repo"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Findings: 0") {
		t.Fatalf("stdout = %q, want findings count", stdout.String())
	}
}

func TestScanEmptyRepoJSON(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"scan", "../../fixtures/empty-repo", "--format", "json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var report model.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout is not valid report JSON: %v\n%s", err, stdout.String())
	}
	if report.Inventory.Manifests == nil {
		t.Fatal("Inventory.Manifests is nil")
	}
	if len(report.Findings) != 0 {
		t.Fatalf("Findings len = %d, want 0", len(report.Findings))
	}
	if len(report.Rules) != 0 {
		t.Fatalf("Rules len = %d, want 0", len(report.Rules))
	}
	if len(report.Profiles) == 0 {
		t.Fatal("Profiles is empty")
	}
	if report.Policy.Rules.Disabled == nil {
		t.Fatal("Policy.Rules.Disabled is nil")
	}
}

func TestScanFormatBeforePath(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"scan", "--format", "human", "../../fixtures/empty-repo"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PkgWarden scan complete") {
		t.Fatalf("stdout = %q, want human report", stdout.String())
	}
}

func TestScanInvalidFormat(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"scan", "../../fixtures/empty-repo", "--format", "sarif"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("exit code = 0, want failure")
	}
	if !strings.Contains(stderr.String(), "unsupported format: sarif") {
		t.Fatalf("stderr = %q, want unsupported format error", stderr.String())
	}
}

func TestScanMissingPath(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"scan"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("exit code = 0, want failure")
	}
	if !strings.Contains(stderr.String(), "scan requires a path") {
		t.Fatalf("stderr = %q, want missing path error", stderr.String())
	}
}

func TestVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "pkgwarden") {
		t.Fatalf("stdout = %q, want version output", stdout.String())
	}
}

func TestHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"help"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "pkgwarden scan") {
		t.Fatalf("stdout = %q, want usage output", stdout.String())
	}
}
