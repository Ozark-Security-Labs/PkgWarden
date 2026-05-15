# Release Policy

PkgWarden releases package the defensive CLI, JSON schema contract, report
renderers, and composite GitHub Action behavior that users rely on in local
review and CI. Releases should be reproducible from a signed or protected
git tag and should include enough compatibility notes for users to decide
whether to upgrade.

## Versioning model

PkgWarden uses semantic versioning for the Go module version and release
tags. Tags use the form `vMAJOR.MINOR.PATCH`, and the tag must match the
version reported by `pkgwarden --version`.

Compatibility expectations:

- **Major** releases may include breaking CLI, schema, configuration,
  report, or GitHub Action changes.
- **Minor** releases may add new commands, flags, schema fields,
  diagnostics, report sections, action inputs, or non-breaking behavior.
- **Patch** releases should contain bug fixes, dependency updates,
  documentation corrections, and release automation fixes.

## Compatibility expectations

### CLI

Documented commands, flags, exit-code meanings, and output-format names are
user-facing behavior. Removing a command, renaming a flag, changing the
meaning of an exit code, or changing default behavior requires a
compatibility note. Additive flags and commands are non-breaking when
existing invocations continue to work.

### JSON schema

The canonical PkgWarden document schema is versioned independently in
`schema_version`. Schema changes must update the schema document,
[docs/SCHEMA.md](SCHEMA.md), examples or golden output when applicable,
and the changelog.

Breaking schema changes include removing required fields, changing field
types, changing enum values, or changing the meaning of existing fields.
Additive fields are acceptable only through documented extension points or
through an intentional schema-version change.

### Configuration

`.pkgwarden.yml` compatibility covers documented keys, default values,
validation behavior, profile definitions, and rule semantics. Removing
keys, changing default enforcement behavior, or changing rule
interpretation requires a compatibility note. New optional keys are
non-breaking when existing policy files continue to load with the same
meaning.

### Reports

Markdown and SARIF are user-facing review outputs. Markdown is optimized
for humans and may receive additive sections in minor releases. SARIF
output should remain suitable for advisory code-scanning integration.
Changes to alert severity, result locations, rule IDs, or report failure
behavior require release-note coverage.

### GitHub Action

The composite action follows the release tag. Existing documented inputs
and outputs should remain stable within a major release after 1.0. New
optional inputs are non-breaking. Removing inputs, changing defaults,
changing artifact behavior, or requiring new workflow permissions requires
a compatibility note.

## Changelog discipline

Every user-visible change should update [CHANGELOG.md](../CHANGELOG.md)
under `Unreleased` before merge. Release pull requests move entries from
`Unreleased` into the new version section and add schema compatibility
notes when relevant.

Use these categories when they fit:

- `Added`
- `Changed`
- `Deprecated`
- `Removed`
- `Fixed`
- `Security`

Keep changelog entries evidence-bound. Do not describe PkgWarden findings
as confirmed vulnerabilities unless the project can mechanically prove
that claim.

## Release checklist

Before creating a release tag, maintainers should verify:

1. `CHANGELOG.md` has a dated section for the release and an empty
   `Unreleased` section.
2. The Go module version reported by `pkgwarden --version` matches the
   intended tag.
3. Schema compatibility notes are present when schema-facing behavior
   changed.
4. The release commit has passed the normal Go CI, repository hygiene, and
   dependency determinism workflows.
5. `go test ./...` passes locally or in CI with `-race` enabled.
6. `go vet ./...` and `gofmt -l .` produce no findings.
7. A clean `go install github.com/Ozark-Security-Labs/PkgWarden/cmd/pkgwarden@vX.Y.Z`
   can run `pkgwarden --help` and `pkgwarden --version`.
8. Release artifacts do not include generated reports, local fixtures,
   credentials, or scanned target source code beyond intended package
   contents.

## Automated release workflow

The release workflow runs on `v*` tags and can also be started manually by
maintainers. It checks that the tag matches the module version, runs
locked tests, builds platform binaries (Linux/macOS/Windows on
amd64/arm64), generates SHA-256 checksums, and creates or updates a GitHub
Release from the changelog section for that version.

The workflow publishes GitHub Release artifacts only. It does not publish
the module to a registry. Registry publication requires a separate
reviewed policy and explicit maintainer approval.

Release artifacts should include:

- platform-specific `pkgwarden` binaries packaged as archives
- `SHA256SUMS`
- provenance metadata when GitHub artifact attestation is available in the
  runner environment

`pkgwarden --version` prints one deterministic line containing the CLI
package version and PkgWarden schema version.

## Supported versions

Supported release lines are documented in [SECURITY.md](../SECURITY.md) and
updated when support windows change.

<!-- TODO: expand release automation details once M4 release workflow lands. -->
