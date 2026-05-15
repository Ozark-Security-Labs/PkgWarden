# Repository Guidelines

Guidance for coding agents working on PkgWarden.

## Project overview

PkgWarden is an open-source repository hardening advisor for package-manager
and dependency-ingestion configuration. It is **not** an SCA scanner, a CVE
database, or a malware-detection tool. PkgWarden inspects package-manager,
dependency-bot, and CI configuration and reports actionable hardening gaps
with file/line evidence.

The product brief lives at [docs/PRODUCT_BRIEF.md](docs/PRODUCT_BRIEF.md) and
the explicit non-goals at [docs/NON_GOALS.md](docs/NON_GOALS.md).

## Safety and scope

- This repository is for defensive, authorized supply-chain hardening work.
- Do not add exploit automation, payload generation, credential theft,
  malware detection, or live-target attack behavior.
- Keep analysis local and offline by default. Network access requires an
  explicit user opt-in.
- Never execute analyzed repository code.
- Treat findings as evidence-bound recommendations unless mechanically
  proven.
- Redact token-shaped values in every output format. Do not invent registry
  URLs or firewall endpoints.

## Repository layout

- `cmd/pkgwarden/` — CLI entrypoint.
- `internal/inventory/` — repository walking and ecosystem detection.
- `internal/config/` — policy loading, profile resolution.
- `internal/parsers/` — YAML, JSON, TOML, INI, and line-aware text parsers.
- `internal/rules/` — rule registry, plus `node/`, `python/`, `bots/`,
  and `ci/` subpackages.
- `internal/reporting/` — human, JSON, Markdown, SARIF, annotation outputs.
- `internal/autofix/` — patch model and safe fix generation (M5+).
- `fixtures/` — fixture repositories and expected outputs.
- `.github/` — workflows, issue templates, ruleset.
- `docs/` — product and implementation documentation.

The Go package layout is documented in detail at
[docs/IMPLEMENTATION_ARCHITECTURE.md](docs/IMPLEMENTATION_ARCHITECTURE.md).

## Build, test, and development commands

```bash
go build ./...
go test ./...
go vet ./...
gofmt -l .
go run ./cmd/pkgwarden version
go run ./cmd/pkgwarden -- scan . --profile baseline --format human
```

## Coding conventions

- Keep public behavior deterministic and test-covered.
- Make parsers line-aware so findings can point at exact lines.
- Every new rule needs at least one passing and one failing fixture.
- Keep rules small and data-driven where possible.
- Implement JSON output as the contract; SARIF and Markdown derive from it.
- Preserve advisory vs enforce mode boundaries.
- Keep output formats stable and documented in
  [docs/SCHEMA.md](docs/SCHEMA.md).
- Vendor-specific profiles (Socket, Veracode) stay repo-evidence based
  unless an explicit API integration is implemented later.

## Issue and PR expectations

- Reference the relevant `PW-###` issue id in commit messages and PR
  descriptions. Issue ids are stable.
- Explain the behavior change.
- Include tests or fixtures for analysis behavior changes.
- Update [CHANGELOG.md](CHANGELOG.md) and `docs/` for user-facing changes.
- Confirm dependency and workflow changes are pinned deterministically.

## Default product decisions

Use these defaults unless changed by maintainers:

- baseline cooldown: 7 days
- strict cooldown: 14 days
- findings include evidence path and line where possible
- all token-like values must be redacted
- `--fix` defaults to dry-run; an explicit apply flag is required to write
- do not invent package firewall or registry URLs
- Socket and Veracode checks are profile-driven and repo-evidence based
  unless an integration is explicitly implemented
