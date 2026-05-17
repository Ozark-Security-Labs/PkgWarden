# PkgWarden

PkgWarden is an open-source repository hardening advisor for package-manager
and dependency-ingestion configuration.

PkgWarden is not an SCA scanner, vulnerability scanner, CVE database, malware
detector, or dependency inventory replacement. It inspects repository
configuration and reports evidence-bound hardening recommendations.

## Current status

This repository is in the M0 foundation milestone. The CLI can inventory
package-manager, CI, and dependency-bot files, execute baseline hardening
rules, and emit deterministic JSON output.

## CLI

```bash
go run ./cmd/pkgwarden -- scan fixtures/empty-repo
go run ./cmd/pkgwarden -- scan fixtures/empty-repo --format human
go run ./cmd/pkgwarden -- scan fixtures/empty-repo --format json
go run ./cmd/pkgwarden -- scan fixtures/rules-missing-lockfile --fail-on medium
go run ./cmd/pkgwarden -- version
go run ./cmd/pkgwarden -- help
```

The scan command accepts `--format human|json` and
`--fail-on info|low|medium|high|critical`. It also accepts
`--profile baseline|strict|socket-firewall|veracode-package-firewall|private-registry`
and `--policy <path>`.

JSON output is the scan contract. The current model is documented in
[docs/scan-output.md](docs/scan-output.md), with the committed schema at
[docs/scan-output.schema.json](docs/scan-output.schema.json).
Human output is a terminal summary grouped by severity, ecosystem, and
category. Evidence descriptions are redacted through shared helpers before any
report format is written.
Policy file behavior is documented in [docs/policy.md](docs/policy.md), with an
example at [examples/.pkgwarden.yml](examples/.pkgwarden.yml).
Parser utility behavior is documented in [docs/parsers.md](docs/parsers.md).
Fixture and golden test guidance is documented in
[docs/fixtures.md](docs/fixtures.md).

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
