# Contributing to PkgWarden

Thanks for helping improve PkgWarden. This repository is early-stage and
design-first. Contributions should preserve the core project boundary:
defensive analysis of repository configuration that you own or are authorized
to assess.

## License

PkgWarden is licensed under the GNU Affero General Public License version 3
only (`AGPL-3.0-only`). By contributing, you agree that your contribution is
submitted under the PkgWarden Contributor License Agreement in
[CLA.md](CLA.md).

## Contributor License Agreement

All non-trivial contributions require CLA acceptance before merge. You can
accept the CLA by signing through an approved CLA workflow, or by confirming
in your pull request that you have read and agree to [CLA.md](CLA.md).

If you are contributing on behalf of an employer or another organization, make
sure you are authorized to submit the contribution under the CLA.

## Useful contribution types

- New package-manager parsers (npm, pnpm, Yarn, Bun, pip, uv, Poetry, and
  future ecosystems)
- Hardening rules across cooldown, lockfile, registry, install-script, and
  firewall posture categories
- Dependency-bot configuration parsers (Dependabot, Renovate)
- GitHub Actions install-command rules
- Test fixtures (paired passing and failing cases)
- Documentation improvements
- Reporting format improvements

Parser contributors should follow the shared contract in
[docs/PARSERS_AND_ADAPTERS.md](docs/PARSERS_AND_ADAPTERS.md). Diagnostic
categories and stable codes should follow
[docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md).

## Ground rules

- Do not add exploit automation, payload generation, credential theft, bypass
  instructions, malware behavior, or live attack workflows.
- Keep analysis local and offline by default. Network access requires an
  explicit opt-in flag.
- Do not execute analyzed repository code.
- Keep findings evidence-bound: include file path and line evidence when
  possible. Do not overstate confidence.
- Add fixtures for new detection behavior.
- Keep advisory and enforce modes distinct.
- Pin GitHub Actions and Go module dependencies deterministically.
- Redact tokens and secret-shaped values in every output format.

## Development

PkgWarden is a Go module. Useful local commands:

```bash
go build ./...
go test ./...
go vet ./...
gofmt -l .
go run ./cmd/pkgwarden -- scan . --format human
go run ./cmd/pkgwarden -- scan . --format json --output pkgwarden.json
```

The minimum supported Go version is documented in
[docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md).

## CI expectations

Pull requests run the Go workspace on Linux, macOS, and Windows. The matrix
runs `gofmt`, `go vet`, the full test suite, and `go build`. The repository
hygiene workflow validates pinned GitHub Actions and dependency determinism.

Dependency and workflow changes should follow the supply-chain policy in
[docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md). Release-facing changes should
follow the versioning and changelog policy in
[docs/RELEASES.md](docs/RELEASES.md). Keep dependency updates separate from
unrelated feature work when practical, include intentional `go.sum` changes,
and review licenses, advisories, and GitHub Actions permissions before merge.

## Pull requests

Before opening a pull request:

- Run `go fmt`, `go vet`, `go test ./...`, and `go build ./...`.
- Reference the relevant `PW-###` issue id in commit messages and the PR
  description.
- Update [CHANGELOG.md](CHANGELOG.md) for user-visible CLI, schema,
  configuration, report, GitHub Action, documentation, or release-process
  changes.
- Include fixtures or reproduction cases for scanner or rule behavior
  changes.
- Call out known limitations and follow-up work.
