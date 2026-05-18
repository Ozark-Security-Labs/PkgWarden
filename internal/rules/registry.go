package rules

import (
	"sort"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

func Registered() []Rule {
	registered := []Rule{
		missingLockfileRule{},
		strictNoopRule{},
	}
	sort.Slice(registered, func(i, j int) bool {
		return registered[i].Metadata().ID < registered[j].Metadata().ID
	})
	return registered
}

type strictNoopRule struct{}

func (strictNoopRule) Metadata() model.Rule {
	return model.Rule{
		ID:          "PW-R000",
		Ecosystem:   "repository",
		Category:    "foundation",
		Severity:    model.SeverityInfo,
		Profiles:    []model.ProfileID{model.ProfileStrict},
		Remediation: "No remediation; this rule verifies rule engine execution.",
		References:  []model.Reference{},
	}
}

func (strictNoopRule) Evaluate(Context) []model.Finding {
	return []model.Finding{}
}
