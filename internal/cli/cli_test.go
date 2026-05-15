package cli

import (
	"bytes"
	"strings"
	"testing"
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
	if !strings.Contains(stdout.String(), `"findings": []`) {
		t.Fatalf("stdout = %q, want empty findings array", stdout.String())
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
