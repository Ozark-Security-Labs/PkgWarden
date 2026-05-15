package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type jsonContext struct {
	kind       byte
	path       string
	index      int
	pendingKey string
	seen       map[string]struct{}
}

func parseJSON(doc *Document, content []byte) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()

	stack := []jsonContext{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			doc.addDiagnostic("parse json: "+err.Error(), offsetLocation(doc.Path, content, decoder.InputOffset()))
			return
		}

		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{', '[':
				path := nextJSONValuePath(stack)
				context := jsonContext{kind: byte(value), path: path}
				if value == '{' {
					context.seen = map[string]struct{}{}
				}
				stack = append(stack, context)
			case '}', ']':
				if len(stack) == 0 {
					doc.addDiagnostic("parse json: unexpected closing delimiter", offsetLocation(doc.Path, content, decoder.InputOffset()))
					return
				}
				stack = stack[:len(stack)-1]
				consumeJSONValue(stack)
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].kind == '{' && stack[len(stack)-1].pendingKey == "" {
				top := &stack[len(stack)-1]
				if _, ok := top.seen[value]; ok {
					doc.addDiagnostic("duplicate key: "+joinPath(top.path, value), offsetLocation(doc.Path, content, decoder.InputOffset()))
				}
				top.seen[value] = struct{}{}
				top.pendingKey = value
				continue
			}
			path := nextJSONValuePath(stack)
			doc.addValue(path, pathKey(path), value, value, offsetLocation(doc.Path, content, decoder.InputOffset()))
			consumeJSONValue(stack)
		default:
			path := nextJSONValuePath(stack)
			text := scalarString(value)
			doc.addValue(path, pathKey(path), text, text, offsetLocation(doc.Path, content, decoder.InputOffset()))
			consumeJSONValue(stack)
		}
	}
	if len(stack) > 0 {
		doc.addDiagnostic("parse json: unexpected end of input", offsetLocation(doc.Path, content, int64(len(content))))
	}
}

func nextJSONValuePath(stack []jsonContext) string {
	if len(stack) == 0 {
		return ""
	}
	top := stack[len(stack)-1]
	switch top.kind {
	case '{':
		return joinPath(top.path, top.pendingKey)
	case '[':
		index := fmt.Sprintf("[%d]", top.index)
		if top.path == "" {
			return index
		}
		return top.path + index
	}
	return ""
}

func consumeJSONValue(stack []jsonContext) {
	if len(stack) == 0 {
		return
	}
	top := &stack[len(stack)-1]
	switch top.kind {
	case '{':
		top.pendingKey = ""
	case '[':
		top.index++
	}
}

func pathKey(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[i+1:]
		}
	}
	return path
}
