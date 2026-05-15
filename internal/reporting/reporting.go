package reporting

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

var ErrWriteFailed = errors.New("write failed")

func WriteHuman(w io.Writer, report model.Report) error {
	if _, err := fmt.Fprintf(w, "PkgWarden scan complete\nTarget: %s\nFindings: %d\n", report.Target, len(report.Findings)); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	return nil
}

func WriteJSON(w io.Writer, report model.Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	return nil
}
