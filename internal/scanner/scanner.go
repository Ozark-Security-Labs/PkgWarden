package scanner

import (
	"fmt"
	"os"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

const schemaVersion = "0.1.0"

func Scan(target string) (model.Report, error) {
	info, err := os.Stat(target)
	if err != nil {
		return model.Report{}, err
	}
	if !info.IsDir() {
		return model.Report{}, fmt.Errorf("target is not a directory: %s", target)
	}

	return model.Report{
		SchemaVersion: schemaVersion,
		Target:        target,
		Inventory:     model.EmptyInventory(),
		Findings:      []model.Finding{},
		Rules:         []model.Rule{},
		Profiles:      model.DefaultProfiles(),
		Policy:        model.EmptyPolicy(),
	}, nil
}
