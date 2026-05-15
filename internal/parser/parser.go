package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

type Format string

const (
	FormatJSON         Format = "json"
	FormatYAML         Format = "yaml"
	FormatTOML         Format = "toml"
	FormatINI          Format = "ini"
	FormatXML          Format = "xml"
	FormatShellConfig  Format = "shell_config"
	FormatRequirements Format = "requirements"
)

type Document struct {
	Path        string
	Format      Format
	Values      []Value
	Diagnostics []Diagnostic
}

type Value struct {
	Path     string
	Key      string
	Value    string
	Raw      string
	Location model.Location
}

type Diagnostic struct {
	Path     string
	Message  string
	Location model.Location
}

type Query struct {
	document Document
}

func Parse(path string, content []byte, format Format) Document {
	doc := Document{
		Path:        filepath.ToSlash(path),
		Format:      format,
		Values:      []Value{},
		Diagnostics: []Diagnostic{},
	}

	switch format {
	case FormatJSON:
		parseJSON(&doc, content)
	case FormatYAML:
		parseYAML(&doc, content)
	case FormatTOML:
		parseTOML(&doc, content)
	case FormatINI:
		parseINI(&doc, content)
	case FormatXML:
		parseXML(&doc, content)
	case FormatShellConfig:
		parseShellConfig(&doc, content)
	case FormatRequirements:
		parseRequirements(&doc, content)
	default:
		doc.addDiagnostic("unsupported parser format: "+string(format), model.Location{Path: doc.Path})
	}

	return doc
}

func DetectFormat(path string) (Format, bool) {
	slashPath := filepath.ToSlash(path)
	lowerPath := strings.ToLower(slashPath)
	base := strings.ToLower(filepath.Base(slashPath))

	switch {
	case base == "package.json" || strings.HasSuffix(base, ".json") || base == ".renovaterc":
		return FormatJSON, true
	case strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml"):
		return FormatYAML, true
	case strings.HasSuffix(base, ".toml"):
		return FormatTOML, true
	case strings.HasSuffix(base, ".ini") || base == "pip.conf":
		return FormatINI, true
	case strings.HasSuffix(base, ".xml"):
		return FormatXML, true
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return FormatRequirements, true
	case base == ".npmrc" || base == ".pnpmrc" || base == ".yarnrc" || base == ".gemrc" || lowerPath == ".cargo/config":
		return FormatShellConfig, true
	}

	return "", false
}

func ParseInventoryFile(target string, item model.InventoryItem) (Document, []model.Warning) {
	if len(item.Locations) == 0 {
		return Document{}, []model.Warning{{Message: "inventory item has no source location"}}
	}

	rel := item.Locations[0].Path
	format, ok := DetectFormat(rel)
	if !ok {
		return Document{
			Path:        rel,
			Values:      []Value{},
			Diagnostics: []Diagnostic{},
		}, []model.Warning{}
	}

	content, err := os.ReadFile(filepath.Join(target, filepath.FromSlash(rel)))
	if err != nil {
		return Document{}, []model.Warning{{Path: rel, Message: err.Error()}}
	}

	doc := Parse(rel, content, format)
	return doc, Warnings(doc)
}

func (d Document) Query() Query {
	return Query{document: d}
}

func (d Document) All(path string) []Value {
	return d.Query().All(path)
}

func (d Document) Last(path string) (Value, bool) {
	return d.Query().Last(path)
}

func (d Document) Get(path string) (Value, bool) {
	return d.Last(path)
}

func (q Query) All(path string) []Value {
	values := []Value{}
	for _, value := range q.document.Values {
		if value.Path == path {
			values = append(values, value)
		}
	}
	return values
}

func (q Query) Last(path string) (Value, bool) {
	values := q.All(path)
	if len(values) == 0 {
		return Value{}, false
	}
	return values[len(values)-1], true
}

func (q Query) Get(path string) (Value, bool) {
	return q.Last(path)
}

func Warnings(doc Document) []model.Warning {
	warnings := make([]model.Warning, 0, len(doc.Diagnostics))
	for _, diagnostic := range doc.Diagnostics {
		warnings = append(warnings, model.Warning{
			Path:    diagnostic.Path,
			Message: diagnostic.Message,
		})
	}
	return warnings
}

func (d *Document) addValue(path string, key string, value string, raw string, location model.Location) {
	if location.Path == "" {
		location.Path = d.Path
	}
	d.Values = append(d.Values, Value{
		Path:     path,
		Key:      key,
		Value:    value,
		Raw:      raw,
		Location: location,
	})
}

func (d *Document) addDiagnostic(message string, location model.Location) {
	if location.Path == "" {
		location.Path = d.Path
	}
	d.Diagnostics = append(d.Diagnostics, Diagnostic{
		Path:     location.Path,
		Message:  message,
		Location: location,
	})
}

func joinPath(parts ...string) string {
	joined := []string{}
	for _, part := range parts {
		if part == "" {
			continue
		}
		joined = append(joined, part)
	}
	return strings.Join(joined, ".")
}

func scalarString(value any) string {
	if value == nil {
		return "null"
	}
	return fmt.Sprint(value)
}
