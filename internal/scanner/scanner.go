package scanner

import (
	"fmt"
	"os"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
	"github.com/Ozark-Security-Labs/PkgWarden/internal/policy"
	"github.com/Ozark-Security-Labs/PkgWarden/internal/rules"
)

const schemaVersion = "0.1.0"

type Options struct {
	Profile    model.ProfileID
	PolicyPath string
}

func Scan(target string) (model.Report, error) {
	return ScanWithOptions(target, Options{})
}

func ScanWithOptions(target string, options Options) (model.Report, error) {
	info, err := os.Stat(target)
	if err != nil {
		return model.Report{}, err
	}
	if !info.IsDir() {
		return model.Report{}, fmt.Errorf("target is not a directory: %s", target)
	}

	inventory, warnings := inventoryFor(target)
	scanPolicy, policyWarnings := policy.LoadOptional(target, options.PolicyPath)
	warnings = append(warnings, policyWarnings...)
	profile := options.Profile
	if profile == "" {
		if len(scanPolicy.Profiles) > 0 {
			profile = scanPolicy.Profiles[0]
		} else {
			profile = model.ProfileBaseline
		}
	}
	if len(scanPolicy.Profiles) == 0 {
		scanPolicy.Profiles = []model.ProfileID{profile}
	}
	result := rules.Execute(rules.Context{
		Target:    target,
		Inventory: inventory,
	}, profile, scanPolicy)

	return model.Report{
		SchemaVersion:      schemaVersion,
		Target:             target,
		Inventory:          inventory,
		Warnings:           warnings,
		Findings:           result.Findings,
		SuppressedFindings: result.SuppressedFindings,
		Rules:              result.Rules,
		Profiles:           model.DefaultProfiles(),
		Policy:             scanPolicy,
	}, nil
}
