# GitHub Action

The PkgWarden GitHub Action is a composite wrapper around the
`pkgwarden` CLI. It runs in advisory mode by default and uploads the
requested report formats as workflow artifacts.

The action lives at the repository root in `action.yml` (added in M4).

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `target` | `.` | Path to scan |
| `profile` | `baseline` | Active profile (`baseline`, `strict`, `socket-firewall`, `veracode-package-firewall`, `private-registry`, `regulated-ci`, `oss-maintainer`) |
| `policy` | `.pkgwarden.yml` | Policy file path (skipped if missing) |
| `mode` | `advisory` | `advisory` or `enforce` |
| `fail-on` | `high` | Severity threshold for `enforce` mode (`critical`, `high`, `medium`, `low`) |
| `output` | `markdown` | Comma-separated formats: `human`, `json`, `markdown`, `sarif` |
| `output-dir` | `pkgwarden-output` | Directory the action writes reports into |
| `upload-sarif` | `false` | Upload SARIF to code scanning (requires `security-events: write`) |
| `upload-artifact` | `true` | Upload `output-dir` as a workflow artifact |
| `version` | `latest` | `pkgwarden` release tag to install, or `latest` |

## Outputs

| Output | Description |
| --- | --- |
| `report-dir` | Directory containing all generated reports |
| `markdown-path` | Path to the Markdown report if generated |
| `json-path` | Path to the JSON report if generated |
| `sarif-path` | Path to the SARIF report if generated |
| `findings-summary` | Severity counts as `critical=N high=N medium=N low=N` |

## Permissions

```yaml
permissions:
  contents: read
```

The default action only needs `contents: read`. SARIF upload requires
`security-events: write`:

```yaml
permissions:
  contents: read
  security-events: write
```

## Basic usage

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

The action writes the Markdown report to the job summary and uploads the
full `output-dir` as an artifact.

## SARIF upload

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

SARIF appears under the repository's code-scanning tab. PkgWarden surfaces
hardening findings as advisory alerts. They are not asserted vulnerabilities
and are categorized accordingly.

## Enforce mode

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

In enforce mode the action writes reports first, then fails the job when
findings meet `fail-on` severity or when scan diagnostics escalate to
error severity. See [DIAGNOSTICS.md](DIAGNOSTICS.md) for exit-code
semantics.

## Pinning the CLI version

Production workflows should pin a specific PkgWarden release rather than
`latest`:

```yaml
- uses: Ozark-Security-Labs/PkgWarden@v1
  with:
    version: "0.1.0"
```

Action pinning (the `@v1` ref) should follow the same SHA-pinning practices
PkgWarden recommends in its own rules; see [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md).

## Action artifacts

The default invocation uploads reports as a workflow artifact named
`pkgwarden-output`. Artifacts inherit GitHub's retention and access
controls; see [DATA_HANDLING.md](DATA_HANDLING.md) for report sensitivity
guidance.

<!-- TODO: lock down action.yml schema during M4 (PW-036). -->
