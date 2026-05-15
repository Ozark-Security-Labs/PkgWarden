# Implementation Architecture

PkgWarden is a single Go module. The package layout below is the intended
end state once M0 completes; early commits may carry a subset.

## Module layout

```text
github.com/Ozark-Security-Labs/PkgWarden
├── cmd/pkgwarden/                CLI entrypoint
├── internal/
│   ├── inventory/                repository walking and ecosystem detection
│   ├── config/                   policy loading, profile resolution
│   ├── parsers/                  YAML/JSON/TOML/INI/text parsers
│   │   ├── ini/                  npmrc, pip.conf, etc.
│   │   ├── pmyaml/               .yarnrc.yml, dependabot.yml, renovate.json5
│   │   └── workflow/             GitHub Actions workflow parsing
│   ├── rules/                    rule engine
│   │   ├── node/                 npm, pnpm, Yarn, Bun rules
│   │   ├── python/               pip, uv, Poetry rules
│   │   ├── bots/                 Dependabot, Renovate rules
│   │   └── ci/                   GitHub Actions install-command rules
│   ├── reporting/                human, JSON, Markdown, SARIF, annotations
│   └── autofix/                  patch model and safe fix generation
├── fixtures/                     fixture repositories and expected outputs
├── docs/                         product and implementation documentation
└── .github/                      workflows, issue templates, ruleset, seed
```

`internal/` packages are private to the module. Re-exporting any of them as
a stable public API requires a separate design decision and major version
bump.

## Internal contracts

### `internal/inventory`

```go
type Item struct {
    Ecosystem      string
    PackageManager string
    ProjectRoot    string
    Manifests      []string
    Lockfiles      []string
    Configs        []string
    CIWorkflows    []string
}

type Walker interface {
    Walk(root string) ([]Item, error)
}
```

### `internal/parsers`

Every parser returns a typed configuration object plus an evidence map:

```go
type Evidence struct {
    File      string
    StartLine int
    EndLine   int
    Snippet   string
}

type EvidenceMap map[string]Evidence // keyed by logical field path
```

Parsers are pure: they take bytes and a file path, they return a typed
value, an evidence map, and an error. They never touch the filesystem
beyond the bytes passed in.

### `internal/rules`

Rules implement a common interface and are registered in a central
registry. Each rule declares the parsed inputs it consumes and is invoked
once per matching inventory item.

```go
type Rule interface {
    ID() string
    Applies(profile string, item inventory.Item) bool
    Check(ctx Context) []Finding
}
```

The `Context` provides typed access to parsed configurations and to
configuration loaded from `.pkgwarden.yml` (severity overrides,
profile-specific tuning).

### `internal/reporting`

JSON is the canonical contract. Human, Markdown, and SARIF reporters derive
from the same finding list. SARIF surfaces severity, confidence, rule ids,
and evidence as result properties; it does not assert vulnerabilities.

## Concurrency model

The scanner is single-threaded by default for deterministic output. Inventory
walking and parsing may parallelize per project root once the JSON contract
is stable, but the report writer remains the synchronization point. Tests
should pin determinism with golden output.

## Error handling

Parse and rule errors are first-class diagnostics, not panics. They appear in
the JSON report alongside findings so that CI consumers can see which files
were skipped and why. Diagnostic categories and codes are documented in
[DIAGNOSTICS.md](DIAGNOSTICS.md).

<!-- TODO: lock down interface signatures during PW-004 and PW-005. -->
