# Repository Guidelines

Guidance for coding agents working on PkgWarden.

## Project overview

PkgWarden is an open-source repository hardening advisor for package-manager
and dependency-ingestion configuration. It is not an SCA scanner, a CVE
database, a vulnerability scanner, or a malware-detection tool. PkgWarden
inspects repository configuration and reports actionable hardening gaps with
file/line evidence when rule logic is available.

## Safety and scope

- This repository is for defensive, authorized supply-chain hardening work.
- Do not add exploit automation, payload generation, credential theft,
  malware detection, or live-target attack behavior.
- Keep analysis local and offline by default. Network access requires an
  explicit user opt-in.
- Never execute analyzed repository code.
- Treat findings as evidence-bound recommendations unless mechanically proven.
- Redact token-shaped values in every output format. Do not invent registry
  URLs or firewall endpoints.

## Repository layout

- `cmd/pkgwarden/` - CLI entrypoint.
- `internal/cli/` - CLI argument parsing and command dispatch.
- `internal/scanner/` - scanner orchestration.
- `internal/reporting/` - human and JSON report output.
- `fixtures/` - fixture repositories for scanner tests.
- `.github/` - workflows, issue templates, and repository rules.
- `docs/` - project and repository documentation.

## Build, test, and development commands

```bash
gofmt -l .
go vet ./...
go test ./...
go build ./cmd/pkgwarden
go run ./cmd/pkgwarden -- scan fixtures/empty-repo --format human
go run ./cmd/pkgwarden -- scan fixtures/empty-repo --format json
```

## Coding conventions

- Keep public behavior deterministic and test-covered.
- Make parsers line-aware so findings can point at exact lines when rule logic
  is added.
- Every new rule needs at least one passing and one failing fixture.
- Keep rules small and data-driven where possible.
- Implement JSON output as the contract; other formats should derive from it.
- Preserve advisory vs enforce mode boundaries.
- Keep output formats stable and documented.

## Issue and PR expectations

- Reference the relevant `PW-###` issue id in commit messages and PR
  descriptions.
- Explain the behavior change.
- Include tests or fixtures for analysis behavior changes.
- Update [CHANGELOG.md](CHANGELOG.md) and docs for user-facing changes.
- Confirm dependency and workflow changes are pinned deterministically.
