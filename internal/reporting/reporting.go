package reporting

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var ErrWriteFailed = errors.New("write failed")

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Target        string    `json:"target"`
	Findings      []Finding `json:"findings"`
}

type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Line     int    `json:"line,omitempty"`
}

func WriteHuman(w io.Writer, report Report) error {
	if _, err := fmt.Fprintf(w, "PkgWarden scan complete\nTarget: %s\nFindings: %d\n", report.Target, len(report.Findings)); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	return nil
}

func WriteJSON(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	return nil
}
