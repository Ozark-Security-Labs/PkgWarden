package rules

import "testing"

func TestInlineSuppressionRequiresReason(t *testing.T) {
	content := "pkgwarden:ignore PW-R001\n{\"name\":\"fixture\"}\n"

	if inlineSuppressionMatches(content, "PW-R001", 2) {
		t.Fatal("inline suppression without reason matched, want no suppression")
	}
}

func TestInlineSuppressionIgnoresWhitespaceOnlyReason(t *testing.T) {
	content := "pkgwarden:ignore PW-R001    \n{\"name\":\"fixture\"}\n"

	if inlineSuppressionMatches(content, "PW-R001", 2) {
		t.Fatal("inline suppression with whitespace-only reason matched, want no suppression")
	}
}

func TestInlineSuppressionAllowsReason(t *testing.T) {
	content := "pkgwarden:ignore PW-R001 fixture reason\n{\"name\":\"fixture\"}\n"

	if !inlineSuppressionMatches(content, "PW-R001", 2) {
		t.Fatal("inline suppression with reason did not match")
	}
}

func TestInlineSuppressionWithoutLineEvidenceRequiresReason(t *testing.T) {
	content := "pkgwarden:ignore PW-R001 fixture reason\n"

	if !inlineSuppressionMatches(content, "PW-R001", 0) {
		t.Fatal("inline suppression in first 10 lines with reason did not match")
	}
}
