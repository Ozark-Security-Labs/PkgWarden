# Scan Output Contract

PkgWarden scan output is the stable JSON contract for scanner, rule, and
reporting behavior. Human output should derive from this model and remain a
summary view.

The schema is committed at [scan-output.schema.json](scan-output.schema.json).

## Top-level fields

- `schema_version` identifies the scan-output contract version.
- `target` is the scanned repository path as provided to the scanner.
- `inventory` records detected ecosystems, package managers, manifests,
  lockfiles, CI workflows, dependency bots, and package-manager config files.
- `warnings` records non-fatal scan problems, such as unreadable paths found
  while walking the target repository.
- `findings` records evidence-bound hardening recommendations.
- `suppressed_findings` records findings hidden by policy or inline
  suppressions.
- `rules` records rule metadata and profile applicability.
- `profiles` records supported hardening profiles.
- `policy` records selected profiles and explicit rule overrides.

## Severity

Severity communicates hardening priority, not exploitability.

- `info`: informational context or hygiene guidance.
- `low`: low-risk hardening gap.
- `medium`: meaningful hardening gap that should be triaged.
- `high`: important hardening gap with broad repository impact.
- `critical`: release-blocking hardening gap for strict environments.

## Confidence

Confidence communicates how directly the finding is supported by local
repository evidence.

- `low`: weak or partial evidence.
- `medium`: clear evidence with some contextual assumptions.
- `high`: direct local evidence from parsed configuration.

## Evidence and locations

Inventory entries include `ecosystem` and `package_manager` guesses when a file
name or path maps to a known package-manager convention. These are best-effort
labels for hardening rules, not dependency resolution results.

Every finding should include one or more `locations` and one or more `evidence`
entries when rule logic can trace the recommendation to repository files. A
location always includes a file path and may include start and end line/column
fields when the parser can identify exact ranges.

Findings that cannot be mechanically traced should remain evidence-bound in the
recommendation text and should not overstate confidence.

Warnings include the target-relative `path` and a human-readable `message`.
Warnings do not fail the scan and should be used for missing or unreadable files
encountered after repository walking has started.

## Profiles and policy

Rules can be enabled by profiles and by explicit policy configuration. Supported
profile identifiers are:

- `baseline`
- `strict`
- `socket-firewall`
- `veracode-package-firewall`
- `private-registry`

Socket Firewall and Veracode Package Firewall are represented as vendor-neutral
profile identifiers. They do not imply API calls, live integration, registry URL
assumptions, or vendor-specific behavior unless a future integration explicitly
adds that behavior.

The `policy.rules.enabled` and `policy.rules.disabled` arrays contain explicit
rule id overrides. The `policy.suppressions` array records policy-file
suppressions with `rule_id`, `path`, and `reason`.
