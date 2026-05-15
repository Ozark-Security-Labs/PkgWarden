package scanner

import (
	"fmt"
	"os"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/reporting"
)

const schemaVersion = "0.1.0"

func Scan(target string) (reporting.Report, error) {
	info, err := os.Stat(target)
	if err != nil {
		return reporting.Report{}, err
	}
	if !info.IsDir() {
		return reporting.Report{}, fmt.Errorf("target is not a directory: %s", target)
	}

	return reporting.Report{
		SchemaVersion: schemaVersion,
		Target:        target,
		Findings:      []reporting.Finding{},
	}, nil
}
