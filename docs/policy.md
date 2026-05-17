# Policy Files

PkgWarden loads `.pkgwarden.yml` from the scanned repository root by default.
Use `--policy <path>` to load a specific policy file instead.

Policy files are local configuration only. Registry and package-firewall
endpoints are recorded in scan output for rules and future integrations; the
foundation scanner does not call them.

```yaml
strict: true
profiles:
  - strict
registries:
  approved:
    - https://registry.npmjs.org
package_firewall:
  endpoints:
    - https://firewall.example.local
  default_cooldown_days: 7
rules:
  enabled:
    - PW-R000
  disabled: []
  severity:
    PW-R001: high
suppressions:
  - rule_id: PW-R001
    path: package.json
    reason: Example suppression reason.
```

## Fields

- `strict` enables schema-error warning wording for policy validation problems.
  Validation remains non-fatal so scans still complete.
- `profiles` selects hardening profiles such as `baseline` or `strict`.
- `registries.approved` records approved registry endpoint URIs.
- `package_firewall.endpoints` records package-firewall endpoint URIs.
- `package_firewall.default_cooldown_days` records a non-negative cooldown
  window for future package-firewall rules.
- `rules.enabled` and `rules.disabled` explicitly enable or disable rule IDs.
- `rules.severity` maps rule IDs to severity overrides.
- `suppressions` requires `rule_id`, `path`, and a non-empty `reason`.

Unknown keys and invalid values are emitted as scan warnings. With
`strict: true`, these warnings are prefixed as policy schema errors.
