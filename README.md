# PkgWarden

PkgWarden is a defensive supply-chain tool for mapping package-manager and
dependency-ingestion hardening posture across a repository.

It answers a simple question:

> Are the package-manager, registry, firewall, lockfile, cooldown,
> dependency-bot, and CI install settings hardened enough to reduce
> supply-chain risk?

PkgWarden is intended for security engineers, AppSec teams, platform
engineers, and maintainers who need a concrete inventory of dependency
ingestion controls and the exact configuration changes required to harden
them.

## Problem

Most teams buy or deploy SCA and package-firewall tooling, but their
repositories still contain weak or incomplete package-manager configuration.
They often cannot answer:

- Which package managers and lockfiles does this repository actually use?
- Are packages fetched from approved registries or a package firewall?
- Is there a cooldown or minimum-release-age in place for new versions?
- Are install scripts allowed to execute during dependency resolution?
- Is the dependency bot moving faster than the package-manager policy?
- Does CI use reproducible, locked install commands?
- Are plaintext credentials present in `.npmrc`, `pip.conf`, or Yarn config?

SCA scanners flag vulnerable dependencies. PkgWarden starts one layer
earlier: inventory the configuration, attach evidence, and make the
acquisition posture reviewable.

## Product thesis

Supply-chain compromise is often a configuration failure before it is a
dependency failure.

If reviewers can see the effective package-acquisition posture of a
repository, they can spot weak cooldowns, registry bypass, missing lockfile
enforcement, and unsafe install behavior before a malicious package lands.

## Current scope

PkgWarden is a local CLI and CI-friendly analyzer that produces a structured
hardening report.

Current built-in targets:

- npm, pnpm, Yarn, and Bun manifests, lockfiles, and config
- pip, uv, and Poetry manifests, lockfiles, and config
- Dependabot and Renovate configuration
- GitHub Actions workflows (install-command analysis)
- `.npmrc`, `pip.conf`, `.yarnrc.yml`, `bunfig.toml`, and equivalent
  config files

Current outputs:

- Human CLI output
- JSON hardening report
- Markdown report (suitable for PR comments)
- SARIF for code-scanning integration
- GitHub Actions job summary and annotations

The canonical JSON contract is documented in
[docs/SCHEMA.md](docs/SCHEMA.md). Diagnostic categories, stable codes, and
CI exit behavior are documented in [docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md).
Project configuration, profiles, approved registries, and rule overrides are
documented in [docs/CONFIGURATION.md](docs/CONFIGURATION.md). Privacy and
data-handling expectations are documented in
[docs/DATA_HANDLING.md](docs/DATA_HANDLING.md). Installation, CLI usage,
report interpretation, examples, and limitations are documented in
[docs/USAGE.md](docs/USAGE.md).

## Example report shape

```text
File: .npmrc:1
Manager: npm
Rule: PW-NPM-001 missing minimum-release-age (cooldown)
Severity: high
Evidence:
  - registry=https://registry.npmjs.org/
  - minimum-release-age not configured
Recommendation:
  - Set minimum-release-age=10080 (7 days) in .npmrc
  - Or set minimum-release-age=20160 (14 days) under strict profile
```

```text
File: .github/dependabot.yml:5
Manager: dependabot
Rule: PW-BOT-002 dependency-bot cooldown shorter than package-manager
Severity: medium
Evidence:
  - dependabot cooldown.default-days: 3
  - .npmrc minimum-release-age: 7 days
Recommendation:
  - Align cooldown.default-days with package-manager minimum-release-age
  - Or remove the package-manager cooldown if intentional
```

## Core concepts

### Profiles

PkgWarden ships with composable profiles that select which rules apply and
how strict each rule is:

- `baseline` — 7-day cooldown, lockfile required, install scripts off by
  default
- `strict` — 14-day cooldown, signed lockfile entries where supported,
  immutable installs in CI
- `socket-firewall` — Socket Firewall posture, repo-evidence only
- `veracode-package-firewall` — Veracode Package Firewall posture,
  repo-evidence only
- `private-registry` — approved-registry enforcement, plaintext-credential
  checks
- `regulated-ci` — locked installs, no network during build, signed releases
- `oss-maintainer` — defaults tuned for upstream maintainers, lighter on
  internal-registry checks

### Rules and evidence

PkgWarden findings are evidence-bound. Every finding includes:

- the rule id and category (cooldown, lockfile, registry, install-scripts,
  credentials, firewall, ci-install)
- the file path and line number where the configuration was observed
- the observed value and the expected value under the active profile
- a concrete recommendation, often expressed as the exact line to change
- optional autofix metadata (M5 and later)

Findings never include the contents of secret-shaped values. Token-like
strings are redacted in every output format.

### Findings, not vulnerabilities

PkgWarden complements SCA scanners and package firewalls; it does not
replace them. It does not maintain a vulnerability database, score package
risk, or detect malware. A clean PkgWarden report does not imply a clean
dependency tree — it implies a hardened acquisition posture.

## Quickstart

```bash
go install github.com/Ozark-Security-Labs/PkgWarden/cmd/pkgwarden@latest
pkgwarden version
pkgwarden scan . --profile baseline --format human
pkgwarden scan . --profile strict --format json --output pkgwarden.json
pkgwarden scan . --profile baseline --format markdown --output pkgwarden.md
```

Release archives contain the `pkgwarden` binary for each supported platform.
Use the generated Markdown for human review and the JSON document for
automation. PkgWarden redacts token-shaped values in generated artifacts, but
reports can still contain registry hostnames and repository configuration and
should be treated as review material. See
[docs/DATA_HANDLING.md](docs/DATA_HANDLING.md) for local analysis, report
sensitivity, CI artifact, SARIF, and sharing guidance.

SARIF is available for advisory GitHub code-scanning integration:

```bash
pkgwarden scan . --format sarif --output pkgwarden.sarif
```

A repository policy file (`.pkgwarden.yml`) can pin the active profile,
declare approved registries, override rule severity, and record suppressions.
See [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

```bash
pkgwarden scan . --policy .pkgwarden.yml --fail-on high
```

See [docs/USAGE.md](docs/USAGE.md) for end-to-end examples, output
interpretation, limitations, and defensive-use guidance.

## Local development

PkgWarden is implemented as a Go module. Supply-chain maintenance, lockfile
review, dependency audit, and release sanity expectations are documented in
[docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md). Versioning, changelog,
compatibility, and tagged release expectations are documented in
[docs/RELEASES.md](docs/RELEASES.md). Useful local commands:

```bash
go run ./cmd/pkgwarden version
go run ./cmd/pkgwarden -- scan . --format human
go run ./cmd/pkgwarden -- scan . --format json --output pkgwarden.json
go run ./cmd/pkgwarden -- scan . --format sarif --output pkgwarden.sarif
go test ./...
go build ./...
go vet ./...
gofmt -l .
```

SARIF output is intended for GitHub code scanning. It emits advisory
hardening alerts and scan diagnostics. PkgWarden risk and classification
details are included as SARIF result properties rather than asserted as
confirmed vulnerabilities.

`pkgwarden scan` supports `--mode advisory|enforce`. In enforce mode the
requested report is written first, then the process exits non-zero when any
finding meets the configured `--fail-on` threshold or when scan diagnostics
escalate to error severity. Warnings remain non-blocking by default.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | CLI usage error, including unsupported `--profile` or `--format` values |
| 10 | Target path does not exist or is not readable |
| 11 | Enforce-mode target exists but contains no supported manifests |
| 12 | Policy file cannot be read, parsed, or validated |
| 13 | Scan pipeline failed for another reason |
| 14 | Report rendering or writing failed |
| 20 | Enforce-mode failure: findings met `--fail-on` threshold after the report was written |

## GitHub Action

```yaml
name: PkgWarden
on:
  pull_request:

permissions:
  contents: read

jobs:
  pkgwarden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: Ozark-Security-Labs/PkgWarden@v1
        with:
          profile: baseline
          output: markdown,json
```

The action writes Markdown output to the job summary and uploads generated
reports as an artifact by default. These outputs can contain registry
hostnames and configuration evidence; see
[docs/DATA_HANDLING.md](docs/DATA_HANDLING.md). SARIF upload is optional and
requires `security-events: write`:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v5
  - uses: Ozark-Security-Labs/PkgWarden@v1
    with:
      profile: baseline
      output: markdown,json,sarif
      upload-sarif: "true"
```

In enforce mode, PkgWarden still writes requested reports first, then
returns exit code `20` when findings meet the `fail-on` threshold:

```yaml
steps:
  - uses: actions/checkout@v5
  - uses: Ozark-Security-Labs/PkgWarden@v1
    with:
      profile: strict
      mode: enforce
      fail-on: high
      output: markdown,json
```

See [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md) for all inputs, outputs,
and permission details.

## Relationship to adjacent projects

PkgWarden complements supply-chain tooling rather than replacing it:

- Veracode SCA, Socket, and OSV-based scanners answer "is this dependency
  vulnerable?". PkgWarden answers "is this repository configured to
  resist a supply-chain compromise?".
- Dependabot, Renovate, and GitHub dependency review keep dependencies
  current and flag vulnerable upgrades. PkgWarden makes sure their
  cooldowns and policies match the package manager.
- Veracode Package Firewall and Socket Firewall enforce policy at the
  registry boundary. PkgWarden checks that the repository is configured to
  use them and not to bypass them.
- [AuthMap](https://github.com/Ozark-Security-Labs/AuthMap) maps
  authorization coverage in application code. PkgWarden maps
  package-acquisition posture in repository configuration. They share the
  Ozark Security Labs evidence-bound finding style.

## Non-goals

PkgWarden is not intended to:

- maintain a CVE database or score package vulnerability
- score package reputation
- detect malware in dependency contents
- replace SCA, package firewall, or dependency-graph products
- scan license compliance
- generate an SBOM as a primary feature
- perform exploitability analysis on findings
- exploit, attack, or modify live registry infrastructure

See [SECURITY.md](SECURITY.md) for authorized-use boundaries and finding
language. PkgWarden reports evidence-bound recommendations unless a finding
is mechanically proven.

## Status

This repository currently contains the product scaffold, Go CLI skeleton,
documentation, CI baseline, and security configuration. The scanner
implementation is tracked in milestone *M0: Project foundation and scanner
core* and downstream milestones; see [docs/ROADMAP.md](docs/ROADMAP.md).
