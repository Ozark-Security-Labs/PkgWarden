package parser

import (
	"strings"
	"unicode/utf8"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

func lineLocation(path string, line int, column int) model.Location {
	return model.Location{
		Path:        path,
		StartLine:   line,
		StartColumn: column,
		EndLine:     line,
		EndColumn:   column,
	}
}

func offsetLocation(path string, content []byte, offset int64) model.Location {
	if offset < 0 {
		offset = 0
	}
	if offset > int64(len(content)) {
		offset = int64(len(content))
	}

	line := 1
	column := 1
	remaining := content[:int(offset)]
	for len(remaining) > 0 {
		r, size := utf8.DecodeRune(remaining)
		if r == '\n' {
			line++
			column = 1
		} else {
			column++
		}
		remaining = remaining[size:]
	}
	return lineLocation(path, line, column)
}

func splitLines(content []byte) []string {
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.Split(text, "\n")
}
