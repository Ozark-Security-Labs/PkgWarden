# Changelog

All notable changes to PkgWarden will be documented here.

This project follows a practical changelog style organized by release.

## Unreleased

- Add the initial Go CLI scaffold for `pkgwarden scan`, `pkgwarden version`, and
  `pkgwarden help`.
- Add human and JSON scan output with grouped finding summaries, evidence
  redaction, and `--fail-on` severity thresholds.
- Add a shared secret-redaction utility for package-manager evidence, including
  URL credentials, bearer-like values, npm auth tokens, and credential
  assignments while preserving environment placeholders.
- Define the scan-output data model for inventory, evidence, findings, rules,
  profiles, policy overrides, and the committed JSON Schema.
- Add repository inventory walking for package-manager files, CI workflows, and
  dependency-bot configuration.
- Add line-aware parser utilities for JSON, YAML, TOML, INI, XML,
  shell-style config, and requirements files.
- Add rule engine execution, baseline profile selection, policy suppression,
  inline suppression, and a sample missing-lockfile finding rule.
- Add grouped `.pkgwarden.yml` policy support for strict validation warnings,
  approved registries, package-firewall endpoints, cooldown days, rule severity
  overrides, and required suppression reasons.
- Add fixture repository golden-output tests and contributor fixture guidance.
- Add CI and local development commands for formatting, vetting, testing, and
  building.
