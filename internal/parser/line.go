package parser

import (
	"strings"
)

type sectionFrame struct {
	indent int
	name   string
}

func parseYAML(doc *Document, content []byte) {
	seen := map[string]int{}
	stack := []sectionFrame{}
	for lineNumber, line := range splitLines(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := splitKeyValue(trimmed, ":")
		if !ok || key == "" {
			doc.addDiagnostic("parse yaml: expected key: value", lineLocation(doc.Path, lineNumber+1, 1))
			continue
		}
		indent := countIndent(line)
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		fullPath := joinPath(sectionPath(stack), key)
		if value == "" {
			stack = append(stack, sectionFrame{indent: indent, name: key})
			continue
		}
		addLineValue(doc, seen, fullPath, key, value, line, lineNumber+1)
	}
}

func parseTOML(doc *Document, content []byte) {
	seen := map[string]int{}
	section := ""
	for lineNumber, line := range splitLines(content) {
		trimmed := stripInlineComment(strings.TrimSpace(line), '#')
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(strings.Trim(trimmed, "[]"))
			continue
		}
		key, value, ok := splitKeyValue(trimmed, "=")
		if !ok || key == "" {
			doc.addDiagnostic("parse toml: expected key = value", lineLocation(doc.Path, lineNumber+1, 1))
			continue
		}
		addLineValue(doc, seen, joinPath(section, key), key, value, line, lineNumber+1)
	}
}

func parseINI(doc *Document, content []byte) {
	seen := map[string]int{}
	section := ""
	for lineNumber, line := range splitLines(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(strings.Trim(trimmed, "[]"))
			continue
		}
		key, value, ok := splitKeyValue(trimmed, "=")
		if !ok {
			key, value, ok = splitKeyValue(trimmed, ":")
		}
		if !ok || key == "" {
			doc.addDiagnostic("parse ini: expected key = value", lineLocation(doc.Path, lineNumber+1, 1))
			continue
		}
		addLineValue(doc, seen, joinPath(section, key), key, value, line, lineNumber+1)
	}
}

func parseShellConfig(doc *Document, content []byte) {
	seen := map[string]int{}
	for lineNumber, line := range splitLines(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "export ")
		key, value, ok := splitKeyValue(trimmed, "=")
		if !ok || key == "" {
			doc.addDiagnostic("parse shell config: expected key=value", lineLocation(doc.Path, lineNumber+1, 1))
			continue
		}
		addLineValue(doc, seen, key, key, value, line, lineNumber+1)
	}
}

func parseRequirements(doc *Document, content []byte) {
	for lineNumber, line := range splitLines(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		value := stripInlineComment(trimmed, '#')
		if value == "" {
			continue
		}
		doc.addValue("line", "line", value, line, lineLocation(doc.Path, lineNumber+1, firstNonSpaceColumn(line)))
	}
}

func addLineValue(doc *Document, seen map[string]int, path string, key string, value string, raw string, line int) {
	seen[path]++
	if seen[path] > 1 {
		doc.addDiagnostic("overridden key: "+path, lineLocation(doc.Path, line, firstNonSpaceColumn(raw)))
	}
	doc.addValue(path, key, unquoteValue(value), raw, lineLocation(doc.Path, line, firstNonSpaceColumn(raw)))
}

func splitKeyValue(line string, separator string) (string, string, bool) {
	index := strings.Index(line, separator)
	if index < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:index]), strings.TrimSpace(line[index+len(separator):]), true
}

func stripInlineComment(value string, marker byte) string {
	inQuote := byte(0)
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\'', '"':
			if inQuote == 0 {
				inQuote = value[i]
			} else if inQuote == value[i] {
				inQuote = 0
			}
		case marker:
			if inQuote == 0 {
				return strings.TrimSpace(value[:i])
			}
		}
	}
	return strings.TrimSpace(value)
}

func unquoteValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func countIndent(line string) int {
	count := 0
	for _, r := range line {
		if r == ' ' {
			count++
			continue
		}
		if r == '\t' {
			count += 4
			continue
		}
		break
	}
	return count
}

func sectionPath(stack []sectionFrame) string {
	parts := []string{}
	for _, frame := range stack {
		parts = append(parts, frame.name)
	}
	return strings.Join(parts, ".")
}

func firstNonSpaceColumn(line string) int {
	for i, r := range line {
		if r != ' ' && r != '\t' {
			return i + 1
		}
	}
	return 1
}
