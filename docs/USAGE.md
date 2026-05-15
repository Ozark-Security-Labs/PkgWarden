# Usage

PkgWarden is a defensive CLI for inspecting package-manager and
dependency-ingestion configuration. It does not require running the target
repository and does not need network access for a default scan.

## Installation

```bash
go install github.com/Ozark-Security-Labs/PkgWarden/cmd/pkgwarden@latest
pkgwarden version
```

Release archives also contain the `pkgwarden` binary for each supported
platform; download from the GitHub Releases page once v0.1 is published.

## Commands

```bash
pkgwarden scan <path>
pkgwarden scan <path> --profile baseline
pkgwarden scan <path> --profile strict
pkgwarden scan <path> --profile socket-firewall
pkgwarden scan <path> --profile veracode-package-firewall
pkgwarden scan <path> --profile private-registry
pkgwarden scan <path> --format human
pkgwarden scan <path> --format json
pkgwarden scan <path> --format markdown
pkgwarden scan <path> --format sarif --output pkgwarden.sarif
pkgwarden scan <path> --policy .pkgwarden.yml
pkgwarden scan <path> --fail-on high
pkgwarden scan <path> --fix --dry-run
pkgwarden scan <path> --fix --apply
pkgwarden version
pkgwarden help
```

`--profile` selects which rules apply. `--policy` points at a
`.pkgwarden.yml` file that pins approved registries, overrides rule
severity, and records suppressions. See [CONFIGURATION.md](CONFIGURATION.md).

## Output formats

Human output is intended for interactive use. JSON is the canonical
machine contract documented in [SCHEMA.md](SCHEMA.md). Markdown is
optimized for pull request comments. SARIF emits advisory hardening alerts
for GitHub code scanning.

```bash
pkgwarden scan . --format human
pkgwarden scan . --format json --output pkgwarden.json
pkgwarden scan . --format markdown --output pkgwarden.md
pkgwarden scan . --format sarif --output pkgwarden.sarif
```

PkgWarden redacts token-shaped values in every output format. Reports can
still contain registry hostnames and repository configuration; see
[DATA_HANDLING.md](DATA_HANDLING.md) for sharing guidance.

## Reading a finding

Each finding includes:

- a stable `rule_id` (for example `npm.cooldown.min_release_age`)
- a severity (`critical`, `high`, `medium`, `low`, `info`)
- a confidence (`high`, `medium`, `low`)
- evidence: one or more `file`, `start_line`, `end_line`, `snippet`
  entries
- a `recommendation.summary` and, when possible, a `recommendation.snippet`
  with the exact line to change

PkgWarden never inserts secrets, organization-specific registry URLs, or
firewall endpoints into recommendations or autofix output unless those
values are present in `.pkgwarden.yml`.

## Advisory vs enforce mode

`pkgwarden scan` supports `--mode advisory|enforce`. In advisory mode, the
process exits 0 even when findings are present. In enforce mode, the
process writes the report first and then exits 20 when any finding meets
`--fail-on` severity. Warnings remain non-blocking by default.

## Suppressions

Findings can be suppressed in `.pkgwarden.yml` with a documented reason.
Suppressed findings appear under `suppressed_findings` in the JSON report
so reviewers can audit them.

## Limitations

PkgWarden is not a vulnerability scanner. It does not score package risk,
detect malware, or evaluate the runtime behavior of dependencies. It
reports hardening posture, not dependency safety. A clean PkgWarden report
does not imply a clean dependency tree.

Heuristic parsers may miss unusual file layouts. Open an issue with a
sanitized reproduction when PkgWarden misclassifies an ecosystem or
overlooks a manifest.

## Defensive-use guidance

PkgWarden is intended for repositories you own or are authorized to
review. Do not run PkgWarden against repositories you do not have
permission to assess. See [SECURITY.md](../SECURITY.md) for authorized-use
boundaries and finding language.

<!-- TODO: expand with concrete fixture-based examples once M0–M2 land. -->
