# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Start here

`AGENTS.md` is the canonical guidance file: it covers safety/scope, the Go package layout, build/test commands, coding conventions, issue/PR expectations, and product defaults. Read it before making changes. This file adds Claude-specific orientation plus the few things `AGENTS.md` does not cover.

Module path: `github.com/Ozark-Security-Labs/PkgWarden` (see `go.mod`, Go 1.23). Current state: scanner core is in the M0 milestone (issues PW-001..PW-010); the CLI in `cmd/pkgwarden/main.go` is a scaffold and most `internal/` packages do not exist yet.

## Authoritative in-repo design docs

When making architectural decisions, consult these before inventing patterns:

- `docs/PRODUCT_BRIEF.md` — what PkgWarden is and is not.
- `docs/NON_GOALS.md` — explicit out-of-scope items (no CVE lookups, no malware detection, no SBOM-as-primary, no license scanning).
- `docs/IMPLEMENTATION_ARCHITECTURE.md` — intended Go package layout.
- `docs/ARCHITECTURE.md` — product-level scanner pipeline.
- `docs/SCHEMA.md` — JSON output contract (the source format; Markdown and SARIF derive from it).
- `docs/DIAGNOSTICS.md` — stable finding codes and CI exit behavior.
- `docs/CONFIGURATION.md` — `.pkgwarden.yml`, profiles, registries, overrides.
- `docs/DATA_HANDLING.md` — privacy and redaction expectations.
- `docs/PARSERS_AND_ADAPTERS.md` — parser conventions (line-aware spans).
- `docs/USAGE.md` — CLI contract.
- `docs/ROADMAP.md`, `docs/RELEASES.md`, `docs/SUPPLY_CHAIN.md`, `docs/GITHUB_ACTION.md`, `docs/EXTERNAL_RESEARCH_REFERENCES.md`.

## Issue convention

Work tracks to live GitHub issues `PW-001..PW-058`. Reference the ID in branch names, commit messages, and PR descriptions. IDs are stable.

## Active workflows

- `.github/workflows/ci.yml` — Go build/test/vet/gofmt across Linux, macOS, Windows.
- `.github/workflows/repo-hygiene.yml` — `Ozark-Security-Labs/deterministic-deps` in advisory mode + whitespace check.
- `.github/workflows/scorecard.yml` — OpenSSF Scorecard.

Pin every GitHub Action to a full commit SHA. Preserve the advisory-vs-enforce boundary on `deterministic-deps` — flipping it to enforce is a maintainer decision, not a routine change.

## Contribution mechanics

- `main` is protected via `.github/rulesets/main-protection.json`. Work on feature branches and open PRs.
- Non-trivial contributions require CLA acceptance — see `CLA.md`.
- License is `AGPL-3.0-only`. Changing license posture means touching `LICENSE`, `README.md`, `CONTRIBUTING.md`, and `CLA.md` together.

## Stop-and-ask cues

Do not, without an explicit maintainer decision:

- Add SCA-style features (CVE lookups, reputation scoring, malware detection, exploitability analysis, license compliance, SBOM as a primary feature). These are explicit non-goals.
- Embed concrete registry, package-firewall, or vendor URLs in code or rules. Vendor profiles stay repo-evidence-based unless an API integration is explicitly scoped.
- Change the cooldown defaults (baseline 7 days, strict 14 days).
- Make `--fix` apply changes by default — dry-run is the default, `--apply` is opt-in.
- Require network access for the default scan.
- Emit unredacted token-shaped values in any output format.
