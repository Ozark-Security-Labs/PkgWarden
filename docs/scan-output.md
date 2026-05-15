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
- `findings` records evidence-bound hardening recommendations.
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

Every finding should include one or more `locations` and one or more `evidence`
entries when rule logic can trace the recommendation to repository files. A
location always includes a file path and may include start and end line/column
fields when the parser can identify exact ranges.

Findings that cannot be mechanically traced should remain evidence-bound in the
recommendation text and should not overstate confidence.

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
rule id overrides. Policy loading is not implemented in the foundation model;
the fields define the output contract for future policy-aware scans.
