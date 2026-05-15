package reporting

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteHuman(t *testing.T) {
	var out bytes.Buffer
	report := Report{
		SchemaVersion: "0.1.0",
		Target:        "fixtures/empty-repo",
		Findings:      []Finding{},
	}

	if err := WriteHuman(&out, report); err != nil {
		t.Fatalf("WriteHuman returned error: %v", err)
	}

	want := "PkgWarden scan complete\nTarget: fixtures/empty-repo\nFindings: 0\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestWriteJSON(t *testing.T) {
	var out bytes.Buffer
	report := Report{
		SchemaVersion: "0.1.0",
		Target:        "fixtures/empty-repo",
		Findings:      []Finding{},
	}

	if err := WriteJSON(&out, report); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	if !json.Valid(out.Bytes()) {
		t.Fatalf("output is not valid JSON: %q", out.String())
	}
	if !strings.Contains(out.String(), `"findings": []`) {
		t.Fatalf("output = %q, want empty findings array", out.String())
	}
}
