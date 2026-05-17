package redaction

import (
	"strings"
	"testing"
)

func TestEvidenceTextRedactsURLCredentials(t *testing.T) {
	got := EvidenceText("registry URL https://user:pass123@registry.example/simple was configured")
	want := "registry URL https://[REDACTED]@registry.example/simple was configured"

	if got != want {
		t.Fatalf("EvidenceText() = %q, want %q", got, want)
	}
}

func TestEvidenceTextRedactsBearerAndAssignmentValues(t *testing.T) {
	input := "Authorization: Bearer abc.def.ghi; password = hunter2; api_key=key-123"
	got := EvidenceText(input)

	for _, raw := range []string{"abc.def.ghi", "hunter2", "key-123"} {
		if strings.Contains(got, raw) {
			t.Fatalf("EvidenceText() = %q, contains raw secret %q", got, raw)
		}
	}
	for _, context := range []string{"Authorization: Bearer [REDACTED]", "password = [REDACTED]", "api_key=[REDACTED]"} {
		if !strings.Contains(got, context) {
			t.Fatalf("EvidenceText() = %q, want context %q", got, context)
		}
	}
}

func TestEvidenceTextRedactsPackageManagerSnippets(t *testing.T) {
	tests := []struct {
		name string
		in   string
		raw  []string
		want []string
	}{
		{
			name: "npmrc",
			in:   "//registry.npmjs.org/:_authToken=npm_secret_token",
			raw:  []string{"npm_secret_token"},
			want: []string{"_authToken=[REDACTED]"},
		},
		{
			name: "pypirc",
			in:   "password: pypi-password",
			raw:  []string{"pypi-password"},
			want: []string{"password: [REDACTED]"},
		},
		{
			name: "pip",
			in:   "index-url = https://pipuser:pippass@pypi.example/simple",
			raw:  []string{"pipuser", "pippass"},
			want: []string{"https://[REDACTED]@pypi.example/simple"},
		},
		{
			name: "poetry",
			in:   "pypi-token.pypi = poetry-token",
			raw:  []string{"poetry-token"},
			want: []string{"pypi-token.pypi = [REDACTED]"},
		},
		{
			name: "nuget",
			in:   "<add key=\"ClearTextPassword\" value=\"nuget-secret\" />",
			raw:  []string{"nuget-secret"},
			want: []string{"ClearTextPassword", "value=\"[REDACTED]\""},
		},
		{
			name: "yarn",
			in:   "npmAuthToken: yarn-secret",
			raw:  []string{"yarn-secret"},
			want: []string{"npmAuthToken: [REDACTED]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvidenceText(tt.in)
			for _, raw := range tt.raw {
				if strings.Contains(got, raw) {
					t.Fatalf("EvidenceText() = %q, contains raw secret %q", got, raw)
				}
			}
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Fatalf("EvidenceText() = %q, want context %q", got, want)
				}
			}
		})
	}
}

func TestEvidenceTextPreservesEnvironmentPlaceholders(t *testing.T) {
	input := "tokens: ${NPM_TOKEN}, $PIP_PASSWORD, %NUGET_TOKEN%, ${{ secrets.YARN_TOKEN }}"
	got := EvidenceText(input)

	if got != input {
		t.Fatalf("EvidenceText() = %q, want placeholders preserved", got)
	}
}
