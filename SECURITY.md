# Security Policy

PkgWarden is security-adjacent software. Please report vulnerabilities
responsibly.

## Reporting a vulnerability

Use GitHub private vulnerability reporting when available. If unavailable,
contact the maintainers through GitHub before publishing details.

Do not open a public issue for sensitive reports.

Include:

- Affected version or commit.
- Reproduction steps.
- Impact.
- Suggested fix if known.

## Scope

Security reports may include:

- Unexpected network access.
- Command execution or unsafe subprocess behavior.
- Path traversal or unsafe file writes.
- Crashes on crafted repositories.
- Incorrect CI failure behavior.
- Suppression bypasses.
- Report or artifact injection.
- Vulnerabilities in generated artifacts.

False positives and false negatives are important, but should usually be
reported with the false-positive/false-negative issue template unless they create
a direct security impact in the tool itself.
