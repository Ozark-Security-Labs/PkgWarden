# Parser Utilities

PkgWarden parser utilities provide a shared, line-aware interface for future
rules. They are local-only helpers and do not execute repository code.

The parser package supports these formats:

- JSON
- YAML
- TOML
- INI
- XML
- shell-style package-manager config files
- line-oriented requirements files

Parsers return a `Document` containing flattened key paths, scalar values, raw
source text, and `model.Location` metadata. Rules should use `Get`, `Last`, or
`All` to query values without depending on the raw file format.

Duplicate or overridden keys are preserved. `All(path)` returns every observed
value for a path, while `Last(path)` and `Get(path)` return the effective final
value. Parser diagnostics can be converted to scanner warnings.

YAML and TOML parsing is intentionally conservative for foundation milestone
configuration analysis. It is designed for common package-manager config
patterns, not full language-spec coverage.
