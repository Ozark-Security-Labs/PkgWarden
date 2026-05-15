# PkgWarden

PkgWarden is an open-source repository hardening advisor for package-manager
and dependency-ingestion configuration.

PkgWarden is not an SCA scanner, vulnerability scanner, CVE database, malware
detector, or dependency inventory replacement. It inspects repository
configuration and reports evidence-bound hardening recommendations.

## Current status

This repository is in the M0 foundation milestone. The CLI can run a minimal
scan and emit deterministic zero-finding output, but package-manager rules are
not implemented yet.

## CLI

```bash
go run ./cmd/pkgwarden -- scan fixtures/empty-repo
go run ./cmd/pkgwarden -- scan fixtures/empty-repo --format human
go run ./cmd/pkgwarden -- scan fixtures/empty-repo --format json
go run ./cmd/pkgwarden -- version
go run ./cmd/pkgwarden -- help
```

The scan command accepts `--format human|json`.

## Development

```bash
gofmt -l .
go vet ./...
go test ./...
go build ./cmd/pkgwarden
```

## Safety posture

- Analysis is local and offline by default.
- PkgWarden does not call vendor APIs in the foundation milestone.
- PkgWarden does not execute analyzed repository code.
- Findings must be evidence-bound and include file and line context when rule
  logic is added.

## License

PkgWarden is licensed under the GNU Affero General Public License version 3 only
(`AGPL-3.0-only`). See [LICENSE](LICENSE).
