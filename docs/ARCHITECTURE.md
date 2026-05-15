# Architecture

PkgWarden is designed around a simple pipeline:

```text
repository tree
  -> inventory walker
  -> package-manager and config parsers
  -> rule engine
  -> finding deduplication and suppression
  -> reporters
```

## Components

### 1. Inventory walker

The walker discovers ecosystems and the file groups associated with each:
manifests, lockfiles, package-manager configuration, dependency-bot
configuration, and CI workflows that touch dependency installation.

Inventory output is normalized into one record per ecosystem/manager pair
per project root:

```json
{
  "ecosystem": "node",
  "package_manager": "pnpm",
  "project_root": ".",
  "manifests": ["package.json"],
  "lockfiles": ["pnpm-lock.yaml"],
  "configs": ["pnpm-workspace.yaml"],
  "ci_workflows": [".github/workflows/ci.yml"]
}
```

### 2. Parsers

Parsers turn discovered files into typed configuration objects with
line-aware evidence. Supported formats include YAML, JSON, TOML, INI, and
line-oriented config files such as `.npmrc`, `pip.conf`, and `.yarnrc.yml`.
The parser abstraction is documented in
[PARSERS_AND_ADAPTERS.md](PARSERS_AND_ADAPTERS.md).

Every parsed value carries the file path and a start/end line range so that
findings can point at the exact place a value lives.

### 3. Rule engine

Rules are small and data-driven. Each rule declares:

- a stable rule id (for example `npm.cooldown.min_release_age`)
- the ecosystems and package managers it applies to
- the profiles under which it is enabled
- a severity, confidence, and category
- a check function that consumes one or more parsed configuration objects
  and emits findings

Rules never write to disk. Autofix is a separate concern handled by the
patch model.

### 4. Finding deduplication and suppression

The engine deduplicates findings by `(rule_id, file, start_line)` and
applies suppressions from `.pkgwarden.yml`. Suppressed findings appear in
the report under a `suppressed_findings` section so reviewers can audit
them.

### 5. Reporters

Reporters consume the finding list and inventory and emit:

- human CLI output
- JSON (the canonical machine contract; see [SCHEMA.md](SCHEMA.md))
- Markdown (suitable for PR comments)
- SARIF (advisory code-scanning integration)
- GitHub Actions annotations and job summary

SARIF results include rule ids, evidence locations, severity, and
confidence as result properties, surfaced as advisory findings rather than
confirmed vulnerabilities.

## Severity guidance

- `critical` — reserved for confirmed dangerous misconfiguration that
  exposes credentials or fully bypasses mandated controls.
- `high` — likely package-ingestion bypass, dependency-confusion risk,
  plaintext registry with credentials, or explicit disabling of required
  enterprise controls.
- `medium` — missing recommended cooldown, lockfile enforcement, frozen
  install, or script hardening.
- `low` — informational or improvement recommendation.
- `info` — posture summary or non-blocking context.

## Profiles

PkgWarden ships these built-in profiles:

- `baseline` — practical defaults suitable for most repositories.
- `strict` — opinionated settings for production-critical repositories.
- `socket-firewall` — baseline plus required Socket registry/wrapper
  evidence where configured.
- `veracode-package-firewall` — baseline plus required Veracode Package
  Firewall/proxy evidence where configured.
- `private-registry` — baseline plus approved-registry and source-mapping
  requirements.
- `regulated-ci` — strict CI lockfile and install controls.
- `oss-maintainer` — hardening tuned for public OSS repositories without
  assuming private registries.

Profile selection lives in `.pkgwarden.yml` or on the command line. See
[CONFIGURATION.md](CONFIGURATION.md).

## Trust boundary

PkgWarden is honest about confidence. Heuristic parsers may miss unusual
file layouts, custom installer scripts, or vendored package-manager
plugins. Reports should expose uncertainty rather than overstate
confidence. Findings include a `confidence` field for that reason.

## Implementation architecture

The Go package layout, internal contracts, and concurrency model are
documented in [IMPLEMENTATION_ARCHITECTURE.md](IMPLEMENTATION_ARCHITECTURE.md).

<!-- TODO: expand pipeline diagrams once parsers and rules land in M0/M1/M2. -->
