# Supply Chain Policy

PkgWarden is a tool for hardening repository supply-chain configuration.
Its own supply-chain posture should set the standard it asks of its users.

## Minimum supported Go version

PkgWarden targets the Go version declared in `go.mod` (`go 1.23` at the
time of writing). The minimum supported Go version (MSGV) is bumped
explicitly in a minor release with a `Changed` changelog entry.

## Module pinning

- `go.mod` declares all direct dependencies.
- `go.sum` is committed and reviewed on every change.
- `go mod tidy` is run before merging changes that touch dependencies.
- New direct dependencies require a brief justification in the PR
  description: what they replace, why they are preferred over the standard
  library, and their license.

The repository's `repo-hygiene` workflow runs `deterministic-deps` against
the manifest and lockfile set defined in `.deterministic-deps.yml`. Open
this workflow's findings in the security tab before merging dependency
changes.

## GitHub Actions pinning

Every workflow pins third-party actions to a full commit SHA. The version
comment after the SHA documents the intended release. Dependabot
(`.github/dependabot.yml`) keeps the SHAs current.

Removing a pinned SHA, switching to a tag-based ref, or adopting a new
action requires a review note explaining why.

## License review

PkgWarden is `AGPL-3.0-only`. New direct dependencies must be compatible
with AGPL distribution. PRs that add dependencies should record the
dependency license in the PR description; copyleft conflicts are
blocking.

## Advisory review

Run `go list -json -deps ./...` and check current Go vulnerability database
matches before merging dependency changes. The release workflow runs
`govulncheck ./...` against tagged releases (added in M4).

When `govulncheck` flags an advisory, treat it as blocking unless the call
site is mechanically demonstrated to be unreachable. Record the analysis
in the PR description.

## Build reproducibility

Release builds are reproducible from a tagged commit:

- `go build` uses module-aware mode with `-trimpath` and pinned `GOFLAGS`.
- The release workflow records `go version` and the commit SHA in
  release-archive metadata.
- The workflow emits `SHA256SUMS` for every archive.
- GitHub artifact attestation is enabled when the runner environment
  supports it.

## Release verification

Consumers can verify a release as follows:

```bash
gh release download v0.1.0 --repo Ozark-Security-Labs/PkgWarden
sha256sum --check SHA256SUMS
```

Provenance metadata is verifiable with `gh attestation verify` when
available.

## Reporting supply-chain issues

Report supply-chain issues in PkgWarden's own dependencies through GitHub
private vulnerability reporting; see [SECURITY.md](../SECURITY.md). Do not
file public issues for unfixed upstream advisories.

<!-- TODO: pin govulncheck workflow once the release pipeline lands (M4). -->
