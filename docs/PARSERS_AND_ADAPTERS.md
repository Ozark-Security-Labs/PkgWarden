# Parsers and adapters

Parsers turn package-manager and CI configuration files into typed
configuration objects with line-aware evidence. Adapters group parsers,
inventory detection, and rules for a single ecosystem.

## Parser contract

Every parser implements the same shape:

```go
type Parser[T any] interface {
    Name() string
    Parse(path string, data []byte) (value T, evidence EvidenceMap, err error)
}
```

Behavior expectations:

- **Pure** — parsers never touch the filesystem beyond the bytes passed
  in. They never run subprocesses or contact the network.
- **Line-aware** — the returned `EvidenceMap` records `file`, `start_line`,
  `end_line`, and a short `snippet` for every logical field. Rules use
  this to attach findings to the exact line a value lives on.
- **Lossless for rules** — rules should never need to re-parse the raw
  bytes. If a parser cannot represent a value, it records a `parser`
  diagnostic rather than silently dropping the field.
- **Deterministic** — given the same input bytes, the parser must return
  the same value and the same evidence map. Maps with non-deterministic
  iteration order must be sorted before use.

## Supported formats

| Format | Parser package | Example files |
| --- | --- | --- |
| YAML | `internal/parsers/pmyaml` | `.yarnrc.yml`, `pnpm-workspace.yaml`, `.github/dependabot.yml` |
| JSON | `internal/parsers/json` | `package.json`, `renovate.json` |
| JSON5 | `internal/parsers/json` | `renovate.json5`, `bun.lockb` headers |
| TOML | `internal/parsers/toml` | `pyproject.toml`, `bunfig.toml` |
| INI | `internal/parsers/ini` | `.npmrc`, `pip.conf` |
| Workflow YAML | `internal/parsers/workflow` | `.github/workflows/*.yml` |
| Line-oriented | `internal/parsers/lines` | `requirements.txt`, `constraints.txt` |

Bun's binary lockfile is treated as opaque for now; only its presence and
metadata header are inspected.

## Adapter contract

An adapter is the per-ecosystem composition of inventory, parsers, and
rules. Each adapter exposes:

```go
type Adapter interface {
    Ecosystem() string
    Detect(root string) ([]inventory.Item, error)
    Rules() []rules.Rule
}
```

Detection walks a project root and emits one `inventory.Item` per
discovered package manager. Multiple package managers can coexist (for
example a Node monorepo with pnpm at the root and npm in a subdirectory).
Detection is responsible for grouping manifests, lockfiles, and configs
into the right item.

## Adding a new ecosystem

The full M0 contract lands in PW-004 and PW-005. The shape today is:

1. Add a new package under `internal/parsers/` for the relevant config
   format if it is not already supported.
2. Add a new adapter under `internal/rules/<ecosystem>/` implementing
   `Adapter`.
3. Register the adapter in the rule engine's adapter table.
4. Add fixtures: at least one passing and one failing repository per
   rule, plus a multi-manager fixture exercising detection.
5. Update [ARCHITECTURE.md](ARCHITECTURE.md),
   [IMPLEMENTATION_ARCHITECTURE.md](IMPLEMENTATION_ARCHITECTURE.md), and
   [SCHEMA.md](SCHEMA.md) when the new ecosystem introduces a new
   category or rule-id namespace.

## Adding a new rule

1. Pick a stable rule id (`{ecosystem}.{category}.{specific_check}`).
2. Declare profile applicability and default severity.
3. Implement the `Check` function consuming the parsed configurations the
   rule needs.
4. Add fixtures (passing and failing).
5. Document the rule in the rule catalog (added in M4) and reference any
   upstream documentation in `references`.

Rules never write to disk and never make network calls. Autofix is a
separate concern handled by the patch model (M5).

<!-- TODO: link to internal/parsers Go docs once PW-004 lands. -->
