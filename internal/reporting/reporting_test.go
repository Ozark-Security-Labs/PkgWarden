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
	report := model.Report{
		SchemaVersion: "0.1.0",
		Target:        "fixtures/empty-repo",
		Inventory:     model.EmptyInventory(),
		Warnings:      []model.Warning{},
		Findings:      []model.Finding{},
		Rules:         []model.Rule{},
		Profiles:      model.DefaultProfiles(),
		Policy:        model.EmptyPolicy(),
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
	report := model.Report{
		SchemaVersion: "0.1.0",
		Target:        "fixtures/empty-repo",
		Inventory:     model.EmptyInventory(),
		Warnings:      []model.Warning{},
		Findings:      []model.Finding{},
		Rules:         []model.Rule{},
		Profiles:      model.DefaultProfiles(),
		Policy:        model.EmptyPolicy(),
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
	for _, field := range []string{`"inventory": {`, `"warnings": []`, `"rules": []`, `"profiles": [`, `"policy": {`} {
		if !strings.Contains(out.String(), field) {
			t.Fatalf("output = %q, want field %s", out.String(), field)
		}
	}
}

func TestWriteHumanWithWarnings(t *testing.T) {
	var out bytes.Buffer
	report := model.Report{
		SchemaVersion: "0.1.0",
		Target:        "fixtures/warnings",
		Inventory:     model.EmptyInventory(),
		Warnings: []model.Warning{
			{Path: "locked", Message: "permission denied"},
		},
		Findings: []model.Finding{},
		Rules:    []model.Rule{},
		Profiles: model.DefaultProfiles(),
		Policy:   model.EmptyPolicy(),
	}

	if err := WriteHuman(&out, report); err != nil {
		t.Fatalf("WriteHuman returned error: %v", err)
	}

	want := "PkgWarden scan complete\nTarget: fixtures/warnings\nFindings: 0\nWarnings: 1\nWarning: locked: permission denied\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}
