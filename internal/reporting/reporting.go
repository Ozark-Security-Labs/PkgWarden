package reporting

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
	"github.com/Ozark-Security-Labs/PkgWarden/internal/redaction"
)

var ErrWriteFailed = errors.New("write failed")

func WriteHuman(w io.Writer, report model.Report) error {
	report = redactedReport(report)
	if _, err := fmt.Fprintf(w, "PkgWarden scan complete\nTarget: %s\nFindings: %d\nSuppressed: %d\n", report.Target, len(report.Findings), len(report.SuppressedFindings)); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	if len(report.Findings) > 0 {
		if _, err := fmt.Fprintln(w); err != nil {
			return fmt.Errorf("%w: %v", ErrWriteFailed, err)
		}
		if err := writeFindingGroups(w, report); err != nil {
			return err
		}
	}
	if len(report.Warnings) == 0 {
		return nil
	}
	if len(report.Findings) > 0 {
		if _, err := fmt.Fprintln(w); err != nil {
			return fmt.Errorf("%w: %v", ErrWriteFailed, err)
		}
	}
	if _, err := fmt.Fprintf(w, "Warnings: %d\n", len(report.Warnings)); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	for _, warning := range report.Warnings {
		if _, err := fmt.Fprintf(w, "Warning: %s: %s\n", warning.Path, warning.Message); err != nil {
			return fmt.Errorf("%w: %v", ErrWriteFailed, err)
		}
	}
	return nil
}

func WriteJSON(w io.Writer, report model.Report) error {
	report = redactedReport(report)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	return nil
}

func writeFindingGroups(w io.Writer, report model.Report) error {
	findings := append([]model.Finding(nil), report.Findings...)
	sort.Slice(findings, func(i, j int) bool {
		leftSeverity := severityRank(findings[i].Severity)
		rightSeverity := severityRank(findings[j].Severity)
		if leftSeverity != rightSeverity {
			return leftSeverity < rightSeverity
		}
		leftEcosystem := ecosystemForFinding(report.Inventory, findings[i])
		rightEcosystem := ecosystemForFinding(report.Inventory, findings[j])
		if leftEcosystem != rightEcosystem {
			return leftEcosystem < rightEcosystem
		}
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return locationString(findings[i].Locations) < locationString(findings[j].Locations)
	})

	for i := 0; i < len(findings); {
		severity := findings[i].Severity
		severityEnd := i
		for severityEnd < len(findings) && findings[severityEnd].Severity == severity {
			severityEnd++
		}
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return fmt.Errorf("%w: %v", ErrWriteFailed, err)
			}
		}
		if _, err := fmt.Fprintf(w, "%s severity (%d)\n", titleSeverity(severity), severityEnd-i); err != nil {
			return fmt.Errorf("%w: %v", ErrWriteFailed, err)
		}
		if err := writeEcosystemGroups(w, report, findings[i:severityEnd]); err != nil {
			return err
		}
		i = severityEnd
	}
	return nil
}

func writeEcosystemGroups(w io.Writer, report model.Report, findings []model.Finding) error {
	for i := 0; i < len(findings); {
		ecosystem := ecosystemForFinding(report.Inventory, findings[i])
		category := findings[i].Category
		groupEnd := i
		for groupEnd < len(findings) && ecosystemForFinding(report.Inventory, findings[groupEnd]) == ecosystem && findings[groupEnd].Category == category {
			groupEnd++
		}
		if _, err := fmt.Fprintf(w, "  %s / %s (%d)\n", ecosystem, category, groupEnd-i); err != nil {
			return fmt.Errorf("%w: %v", ErrWriteFailed, err)
		}
		for _, finding := range findings[i:groupEnd] {
			if _, err := fmt.Fprintf(w, "    - %s: %s\n", finding.RuleID, finding.Title); err != nil {
				return fmt.Errorf("%w: %v", ErrWriteFailed, err)
			}
			if location := locationString(finding.Locations); location != "" {
				if _, err := fmt.Fprintf(w, "      Location: %s\n", location); err != nil {
					return fmt.Errorf("%w: %v", ErrWriteFailed, err)
				}
			}
			if len(finding.Evidence) > 0 && finding.Evidence[0].Description != "" {
				if _, err := fmt.Fprintf(w, "      Evidence: %s\n", finding.Evidence[0].Description); err != nil {
					return fmt.Errorf("%w: %v", ErrWriteFailed, err)
				}
			}
			if finding.Recommendation != "" {
				if _, err := fmt.Fprintf(w, "      Recommendation: %s\n", finding.Recommendation); err != nil {
					return fmt.Errorf("%w: %v", ErrWriteFailed, err)
				}
			}
		}
		i = groupEnd
	}
	return nil
}

func redactedReport(report model.Report) model.Report {
	report.Findings = redactedFindings(report.Findings)
	report.SuppressedFindings = redactedFindings(report.SuppressedFindings)
	report.Policy = redactedPolicy(report.Policy)
	return report
}

func redactedPolicy(policy model.Policy) model.Policy {
	if policy.Registries != nil {
		registries := *policy.Registries
		registries.Approved = redactedStrings(policy.Registries.Approved)
		policy.Registries = &registries
	}
	if policy.PackageFirewall != nil {
		firewall := *policy.PackageFirewall
		firewall.Endpoints = redactedStrings(policy.PackageFirewall.Endpoints)
		policy.PackageFirewall = &firewall
	}
	return policy
}

func redactedStrings(values []string) []string {
	if values == nil {
		return nil
	}
	redacted := make([]string, len(values))
	for i, value := range values {
		redacted[i] = redaction.EvidenceText(value)
	}
	return redacted
}

func redactedFindings(findings []model.Finding) []model.Finding {
	if findings == nil {
		return nil
	}
	redacted := make([]model.Finding, len(findings))
	copy(redacted, findings)
	for i := range redacted {
		if redacted[i].Evidence == nil {
			continue
		}
		redacted[i].Evidence = append([]model.Evidence(nil), redacted[i].Evidence...)
		for j := range redacted[i].Evidence {
			redacted[i].Evidence[j].Description = redactEvidence(redacted[i].Evidence[j].Description)
		}
	}
	return redacted
}

func redactEvidence(description string) string {
	return redaction.EvidenceText(description)
}

func ecosystemForFinding(inventory model.Inventory, finding model.Finding) string {
	if len(finding.Locations) == 0 {
		return "unknown"
	}
	path := finding.Locations[0].Path
	for _, items := range [][]model.InventoryItem{
		inventory.Manifests,
		inventory.Lockfiles,
		inventory.PackageManagerConfigFiles,
		inventory.Ecosystems,
		inventory.PackageManagers,
	} {
		for _, item := range items {
			if !hasLocation(item.Locations, path) {
				continue
			}
			if item.Ecosystem != "" {
				return item.Ecosystem
			}
			if item.Kind == "ecosystem" && item.Name != "" {
				return item.Name
			}
		}
	}
	return "unknown"
}

func hasLocation(locations []model.Location, path string) bool {
	for _, location := range locations {
		if location.Path == path {
			return true
		}
	}
	return false
}

func locationString(locations []model.Location) string {
	if len(locations) == 0 {
		return ""
	}
	location := locations[0]
	if location.StartLine > 0 {
		return fmt.Sprintf("%s:%d", location.Path, location.StartLine)
	}
	return location.Path
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 0
	case model.SeverityHigh:
		return 1
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 3
	case model.SeverityInfo:
		return 4
	default:
		return 5
	}
}

func titleSeverity(severity model.Severity) string {
	if severity == "" {
		return "Unknown"
	}
	return strings.ToUpper(string(severity[:1])) + string(severity[1:])
}
