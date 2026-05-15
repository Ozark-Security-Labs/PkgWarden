# Diagnostics

Diagnostics are scan-time messages that are not findings: parser errors,
missing files, unsupported formats, and configuration validation issues.
They appear in the JSON report under `diagnostics` so CI consumers can see
which files were skipped and why.

## Severity buckets

| Severity | Meaning |
| --- | --- |
| `info` | Informational. The scan continued normally. |
| `warning` | A file was skipped or partially parsed. The rest of the scan continued. |
| `error` | A required input was unreadable or the scan could not complete a section. |
| `fatal` | The scan could not produce a report. |

In advisory mode, warnings and errors do not change the process exit code.
In enforce mode, errors and fatals participate in `--fail-on` evaluation.

## Categories

| Category | Examples |
| --- | --- |
| `walker` | Path traversal errors, permission denied on a project root |
| `parser` | YAML/JSON/TOML parse errors, malformed `.npmrc` |
| `inventory` | Unknown ecosystem, no manifests found in enforce-mode target |
| `policy` | `.pkgwarden.yml` validation errors, unknown profile name |
| `rule` | Rule registration errors, profile applicability misconfiguration |
| `reporting` | Report rendering or writing errors |

## Stable codes

Codes use the form `PW-DIAG-{category}-{number}` and remain stable across
patch and minor releases. Code documentation lands during M0 (issues
PW-004 and PW-005) and grows alongside rules and parsers.

## Exit codes

PkgWarden's process exit codes:

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

The report is always written before a non-zero exit, so CI consumers can
inspect the diagnostics and findings that triggered the failure.

## Advisory vs enforce mode

`--mode advisory` is the default. The process exits 0 unless a structural
problem (10–14) prevents the scan or report from completing.

`--mode enforce` adds finding-driven failure. The report is written first,
and the process then exits 20 when findings meet `--fail-on` severity or
when any diagnostic is of severity `error` or higher.

<!-- TODO: enumerate stable diagnostic codes during PW-004 and PW-005. -->
