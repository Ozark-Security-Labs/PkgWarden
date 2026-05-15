# JSON Schema

PkgWarden's JSON output is the canonical contract. Human, Markdown, and
SARIF reporters derive from the same data. Downstream automation should
consume JSON.

The draft JSON Schema lives at `schemas/pkgwarden.schema.json` (added in
M0). This document explains field meanings.

## Document shape

```json
{
  "tool": "PkgWarden",
  "version": "0.1.0",
  "schema_version": "1",
  "target": ".",
  "profile": "baseline",
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 4,
    "low": 2,
    "info": 1
  },
  "inventory": [ ... ],
  "findings": [ ... ],
  "suppressed_findings": [ ... ],
  "diagnostics": [ ... ]
}
```

### Top-level fields

- `tool` — always `"PkgWarden"`.
- `version` — the CLI version that produced the report.
- `schema_version` — the document schema version. Independent of `version`.
- `target` — the scanned path, as provided on the CLI.
- `profile` — the effective profile name after policy resolution.
- `summary` — counts per severity. Convenient for dashboards.
- `inventory` — per-ecosystem records (see ARCHITECTURE.md).
- `findings` — the primary array.
- `suppressed_findings` — findings matched by suppressions in
  `.pkgwarden.yml`. Includes the matching suppression metadata.
- `diagnostics` — parser errors, missing files, and other scan-time
  messages. Diagnostic categories and codes are documented in
  [DIAGNOSTICS.md](DIAGNOSTICS.md).

## Finding object

```json
{
  "rule_id": "pnpm.cooldown.minimum_release_age",
  "title": "pnpm minimumReleaseAge is not configured",
  "severity": "medium",
  "confidence": "high",
  "category": "cooldown",
  "ecosystem": "node",
  "package_manager": "pnpm",
  "message": "Configure a release-age gate before accepting newly published packages.",
  "evidence": [
    {
      "file": "pnpm-workspace.yaml",
      "start_line": 12,
      "end_line": 12,
      "snippet": "minimumReleaseAge: 0"
    }
  ],
  "recommendation": {
    "summary": "Set minimumReleaseAge to at least 10080 minutes for the baseline profile.",
    "snippet": "minimumReleaseAge: 10080"
  },
  "autofix": {
    "available": true,
    "safety": "safe",
    "requires_review": false
  },
  "references": [
    "https://pnpm.io/settings#minimumreleaseage"
  ]
}
```

### Required fields

- `rule_id` — stable identifier. Format
  `{ecosystem}.{category}.{specific_check}` for ecosystem rules,
  `{area}.{category}.{specific_check}` for bot/CI/firewall rules.
- `title` — short human-readable label.
- `severity` — one of `critical`, `high`, `medium`, `low`, `info`.
- `category` — one of `cooldown`, `lockfile`, `registry`, `install-scripts`,
  `credentials`, `firewall`, `ci-install`, `dependency-bot`,
  `dependency-specifier`, `posture-summary`.
- `message` — one-paragraph explanation.
- `recommendation` — object with at least `summary`.

### Optional fields

- `confidence` — one of `high`, `medium`, `low`. Reflects parser
  certainty, not the importance of the finding.
- `ecosystem` and `package_manager` — populated for ecosystem-scoped
  rules.
- `evidence` — array of file/line records. Always present when the rule
  could attach evidence; rules that summarize posture may omit it.
- `autofix` — present when the rule supports patch generation. `safety`
  is `safe`, `review`, or `none`.
- `references` — links to upstream package-manager documentation.

## Severity and confidence semantics

Severity reflects security impact under the active profile. Confidence
reflects how certain PkgWarden is that the evidence matches the rule
description. A `medium`/`high` finding (medium impact, high parser
confidence) is the most common shape.

PkgWarden reports evidence-bound recommendations, not confirmed
vulnerabilities. SARIF results carry these fields as result properties so
that downstream consumers can decide how to display them.

## Suppression object

```json
{
  "rule_id": "node.dependency_specifier.exotic",
  "path": "package.json",
  "package": "internal-local-tool",
  "reason": "Workspace-local tool used only in development.",
  "suppressed_at": "2026-05-15T00:00:00Z"
}
```

Suppressed findings always include the suppression reason and the matched
suppression entry, not just the original finding.

<!-- TODO: publish schemas/pkgwarden.schema.json in M0 (PW-002 / PW-007). -->
