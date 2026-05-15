package parser

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

type xmlFrame struct {
	name  string
	path  string
	count map[string]int
}

func parseXML(doc *Document, content []byte) {
	decoder := xml.NewDecoder(bytes.NewReader(content))
	stack := []xmlFrame{}

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			doc.addDiagnostic("parse xml: "+err.Error(), offsetLocation(doc.Path, content, decoder.InputOffset()))
			return
		}

		switch value := token.(type) {
		case xml.StartElement:
			name := value.Name.Local
			parentPath := ""
			if len(stack) > 0 {
				parent := &stack[len(stack)-1]
				parent.count[name]++
				parentPath = parent.path
			}
			path := joinPath(parentPath, name)
			frame := xmlFrame{name: name, path: path, count: map[string]int{}}
			stack = append(stack, frame)
			for _, attr := range value.Attr {
				attrPath := joinPath(path, "@"+attr.Name.Local)
				doc.addValue(attrPath, attr.Name.Local, attr.Value, attr.Value, offsetLocation(doc.Path, content, decoder.InputOffset()))
			}
		case xml.CharData:
			text := strings.TrimSpace(string(value))
			if text == "" || len(stack) == 0 {
				continue
			}
			path := stack[len(stack)-1].path
			doc.addValue(path, stack[len(stack)-1].name, text, text, offsetLocation(doc.Path, content, decoder.InputOffset()))
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
}
