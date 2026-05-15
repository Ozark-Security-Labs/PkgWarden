package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

func TestParseJSONLocationsAndDuplicates(t *testing.T) {
	doc := Parse("package.json", []byte("{\n  \"scripts\": {\"test\": \"go test\", \"test\": \"go test ./...\"},\n  \"private\": true\n}\n"), FormatJSON)

	if len(doc.Diagnostics) == 0 {
		t.Fatal("Diagnostics len = 0, want duplicate key diagnostic")
	}
	values := doc.All("scripts.test")
	if len(values) != 2 {
		t.Fatalf("scripts.test values len = %d, want 2", len(values))
	}
	last, ok := doc.Last("scripts.test")
	if !ok {
		t.Fatal("scripts.test missing")
	}
	if last.Value != "go test ./..." {
		t.Fatalf("scripts.test last = %q, want effective value", last.Value)
	}
	if last.Location.StartLine != 2 {
		t.Fatalf("scripts.test line = %d, want 2", last.Location.StartLine)
	}
	if value, ok := doc.Get("private"); !ok || value.Value != "true" {
		t.Fatalf("private = %q, %v; want true", value.Value, ok)
	}
}

func TestParseMalformedInputsReturnDiagnostics(t *testing.T) {
	tests := []struct {
		name    string
		format  Format
		content string
	}{
		{name: "json", format: FormatJSON, content: `{"name":`},
		{name: "yaml", format: FormatYAML, content: `name`},
		{name: "toml", format: FormatTOML, content: `name`},
		{name: "ini", format: FormatINI, content: `name`},
		{name: "xml", format: FormatXML, content: `<project>`},
		{name: "shell", format: FormatShellConfig, content: `registry`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := Parse("fixture", []byte(tt.content), tt.format)
			if len(doc.Diagnostics) == 0 {
				t.Fatal("Diagnostics len = 0, want parse diagnostic")
			}
			if doc.Diagnostics[0].Path == "" {
				t.Fatal("Diagnostic path is empty")
			}
		})
	}
}

func TestLineParsersExposeLocationsAndOverrides(t *testing.T) {
	tests := []struct {
		name    string
		format  Format
		content string
		path    string
		want    string
	}{
		{name: "yaml", format: FormatYAML, content: "registry:\n  url: https://one\n  url: https://two\n", path: "registry.url", want: "https://two"},
		{name: "toml", format: FormatTOML, content: "[registry]\nurl = \"https://one\"\nurl = \"https://two\"\n", path: "registry.url", want: "https://two"},
		{name: "ini", format: FormatINI, content: "[registry]\nurl=https://one\nurl=https://two\n", path: "registry.url", want: "https://two"},
		{name: "shell", format: FormatShellConfig, content: "registry=https://one\nregistry=https://two\n", path: "registry", want: "https://two"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := Parse("config", []byte(tt.content), tt.format)
			values := doc.All(tt.path)
			if len(values) != 2 {
				t.Fatalf("%s values len = %d, want 2", tt.path, len(values))
			}
			last, ok := doc.Last(tt.path)
			if !ok {
				t.Fatalf("%s missing", tt.path)
			}
			if last.Value != tt.want {
				t.Fatalf("%s last = %q, want %q", tt.path, last.Value, tt.want)
			}
			if last.Location.StartLine == 0 {
				t.Fatal("last value has no source line")
			}
			if len(doc.Diagnostics) == 0 || !strings.Contains(doc.Diagnostics[0].Message, "overridden key") {
				t.Fatalf("diagnostics = %#v, want overridden key diagnostic", doc.Diagnostics)
			}
		})
	}
}

func TestParseXMLLocations(t *testing.T) {
	doc := Parse("pom.xml", []byte("<project><repositories><repository id=\"central\">enabled</repository></repositories></project>"), FormatXML)

	if value, ok := doc.Get("project.repositories.repository"); !ok || value.Value != "enabled" {
		t.Fatalf("repository text = %q, %v; want enabled", value.Value, ok)
	}
	if value, ok := doc.Get("project.repositories.repository.@id"); !ok || value.Value != "central" {
		t.Fatalf("repository id = %q, %v; want central", value.Value, ok)
	}
}

func TestRequirementsParserReturnsLineValues(t *testing.T) {
	doc := Parse("requirements.txt", []byte("# comment\nrequests==2.31.0 # pinned\npytest\n"), FormatRequirements)

	values := doc.All("line")
	if len(values) != 2 {
		t.Fatalf("line values len = %d, want 2", len(values))
	}
	if values[0].Value != "requests==2.31.0" {
		t.Fatalf("first value = %q, want stripped requirement", values[0].Value)
	}
	if values[0].Location.StartLine != 2 {
		t.Fatalf("first value line = %d, want 2", values[0].Location.StartLine)
	}
}

func TestFormatIndependentQuery(t *testing.T) {
	inputs := []struct {
		format  Format
		content string
	}{
		{format: FormatJSON, content: `{"registry":{"url":"https://registry.example"}}`},
		{format: FormatYAML, content: "registry:\n  url: https://registry.example\n"},
		{format: FormatTOML, content: "[registry]\nurl = \"https://registry.example\"\n"},
		{format: FormatINI, content: "[registry]\nurl=https://registry.example\n"},
	}

	for _, input := range inputs {
		doc := Parse("config", []byte(input.content), input.format)
		value, ok := doc.Get("registry.url")
		if !ok {
			t.Fatalf("%s registry.url missing", input.format)
		}
		if value.Value != "https://registry.example" {
			t.Fatalf("%s registry.url = %q, want common value", input.format, value.Value)
		}
	}
}

func TestParseInventoryFileWarnings(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{\"name\":"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	item := model.InventoryItem{
		Locations: []model.Location{{Path: "package.json"}},
	}
	doc, warnings := ParseInventoryFile(root, item)
	if len(doc.Diagnostics) == 0 {
		t.Fatal("Diagnostics len = 0, want malformed JSON diagnostic")
	}
	if len(warnings) == 0 {
		t.Fatal("Warnings len = 0, want warning from diagnostic")
	}
	if warnings[0].Path != "package.json" {
		t.Fatalf("warning path = %q, want package.json", warnings[0].Path)
	}
}
