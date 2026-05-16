# Changelog

All notable changes to PkgWarden will be documented here.

This project follows a practical changelog style organized by release.

## Unreleased

- Add the initial Go CLI scaffold for `pkgwarden scan`, `pkgwarden version`, and
  `pkgwarden help`.
- Add minimal human and JSON scan output with zero findings for the foundation
  milestone.
- Define the scan-output data model for inventory, evidence, findings, rules,
  profiles, policy overrides, and the committed JSON Schema.
- Add repository inventory walking for package-manager files, CI workflows, and
  dependency-bot configuration.
- Add line-aware parser utilities for JSON, YAML, TOML, INI, XML,
  shell-style config, and requirements files.
- Add rule engine execution, baseline profile selection, policy suppression,
  inline suppression, and a sample missing-lockfile finding rule.
- Add CI and local development commands for formatting, vetting, testing, and
  building.
