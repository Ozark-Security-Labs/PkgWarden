# Configuration

PkgWarden reads policy from a `.pkgwarden.yml` file at the repository root.
Policy selects the active profile, declares approved registries and package
firewalls, overrides rule severity, and records suppressions.

## File location and precedence

PkgWarden resolves configuration in this order, highest precedence first:

1. CLI flags (`--profile`, `--fail-on`, `--policy`, `--format`).
2. `--policy <path>` if provided on the command line.
3. `.pkgwarden.yml` at the scanned target root.
4. Profile defaults.

Unknown keys in `.pkgwarden.yml` produce a `policy` diagnostic so typos do
not silently disable rules.

## Schema

```yaml
version: 1

profile: baseline   # baseline | strict | socket-firewall | veracode-package-firewall | private-registry | regulated-ci | oss-maintainer

cooldown:
  baseline_days: 7
  strict_days: 14

approved_registries:
  npm:
    - name: internal-npm-proxy
      url: https://packages.example.com/npm/
      scopes:
        - "@example"
  pypi:
    - name: internal-pypi-proxy
      url: https://packages.example.com/pypi/simple/

package_firewalls:
  socket:
    enabled: false
    registry_urls: []
  veracode:
    enabled: false
    registry_urls: []

rules:
  npm.cooldown.min_release_age:
    severity: medium
    min_days: 7

suppressions:
  - rule_id: node.dependency_specifier.exotic
    path: package.json
    package: "internal-local-tool"
    reason: "Workspace-local tool used only in development. Reviewed by AppSec on 2026-05-15."
```

### `version`

Schema version. `1` is the only currently supported value. PkgWarden
refuses to run when `version` is missing or unrecognized.

### `profile`

The active profile name. Profiles are documented in
[ARCHITECTURE.md](ARCHITECTURE.md). The CLI `--profile` flag overrides
this value.

### `cooldown`

Default cooldown thresholds. PkgWarden ships with `baseline_days: 7` and
`strict_days: 14`. Per-rule overrides under `rules` win.

### `approved_registries`

Per-ecosystem lists of approved registries. Each entry has a `name` and a
`url`. Optional `scopes` (npm) restrict the registry to specific scopes.
Findings that detect registry bypass cross-check observed URLs against
this list.

### `package_firewalls`

Enables Socket Firewall and Veracode Package Firewall posture checks
without contacting an external API. When `enabled: true`, PkgWarden expects
to see evidence (configuration, registry URLs) that the firewall is
actively used.

### `rules`

Per-rule overrides keyed by rule id. Recognized keys:

- `severity` — promote or demote the rule's severity for this repository.
- `enabled` — set to `false` to disable the rule entirely.
- Rule-specific keys (for example `min_days` on a cooldown rule).

Unknown rule ids produce a `policy` diagnostic.

### `suppressions`

A list of suppression entries. Each entry requires:

- `rule_id` — the rule being suppressed.
- `reason` — non-empty justification. PkgWarden surfaces this in reports.
- Optional `path`, `package`, or other matchers depending on the rule.

Suppressed findings appear under `suppressed_findings` in the JSON report
so they remain auditable.

## Validation

`pkgwarden scan` validates `.pkgwarden.yml` before walking the repository.
Validation errors produce exit code `12` and a `policy` diagnostic. The
validation pass also normalizes URLs and warns on duplicate registries.

<!-- TODO: cover custom-rule registration once the plugin design lands (M7). -->
