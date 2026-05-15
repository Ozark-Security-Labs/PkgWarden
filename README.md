# PkgWarden

PkgWarden is an open-source repository hardening advisor for package-manager
and dependency-ingestion configuration.

PkgWarden is not an SCA scanner, vulnerability scanner, CVE database, malware
detector, or dependency inventory replacement. It inspects repository
configuration and reports evidence-bound hardening recommendations.

## Current status

This repository is in the M0 foundation milestone. The CLI can inventory
package-manager, CI, and dependency-bot files and emit deterministic
zero-finding output, but package-manager rules are not implemented yet.

## CLI

```bash
go run ./cmd/pkgwarden -- scan fixtures/empty-repo
go run ./cmd/pkgwarden -- scan fixtures/empty-repo --format human
go run ./cmd/pkgwarden -- scan fixtures/empty-repo --format json
go run ./cmd/pkgwarden -- version
go run ./cmd/pkgwarden -- help
```

The scan command accepts `--format human|json`.

JSON output is the scan contract. The current model is documented in
[docs/scan-output.md](docs/scan-output.md), with the committed schema at
[docs/scan-output.schema.json](docs/scan-output.schema.json).
Parser utility behavior is documented in [docs/parsers.md](docs/parsers.md).

Repository inventory walks skip common generated, vendored, cache, and
environment directories such as `.git`, `node_modules`, `vendor`, `.venv`,
`dist`, `build`, and `target`.

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
- Socket Firewall and Veracode Package Firewall are modeled as profiles, not
  hard-coded vendor assumptions.

## License

PkgWarden is licensed under the GNU Affero General Public License version 3 only
(`AGPL-3.0-only`). See [LICENSE](LICENSE).
