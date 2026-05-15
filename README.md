# Ozark Security Labs Repository Template

Private starter repository for Ozark Security Labs open-source security tooling.

This template captures the common repository features currently shared across
`SecFlow`, `rulepath`, and `deterministic-deps`:

- AGPL-3.0-only license baseline.
- Contributor License Agreement placeholder.
- Contribution, support, security, changelog, and conduct docs.
- GitHub issue templates for bugs, features, rules, docs, and false positives/negatives.
- Pull request checklist tuned for security tooling.
- Active Dependabot configuration for GitHub Actions.
- Optional Dependabot expansion template for npm and Cargo projects.
- Repository hygiene workflow with pinned GitHub Actions and `deterministic-deps`.
  SARIF upload is disabled by default so the private template works without GitHub Advanced Security.
- Optional language-specific CI workflow templates for Rust and Node/TypeScript projects.
- Common `.gitignore`, `.editorconfig`, `.gitattributes`, and deterministic-deps config.

## Use

Create a new repository from this template, then replace placeholders:

- `PROJECT_NAME`
- `PROJECT_SLUG`
- `PROJECT_DESCRIPTION`
- `PRIMARY_LANGUAGE`
- `PACKAGE_ECOSYSTEMS`
- `CONTACT_METHOD`

Recommended first edit:

```bash
python scripts/apply-template.py \
  --name "Project Name" \
  --slug project-slug \
  --description "Short project description" \
  --language rust
```

The script is intentionally simple string replacement. Review the result before
pushing a public repository.

## License posture

The template defaults to `AGPL-3.0-only`, matching the current Ozark Security
Labs open-source commercial posture. If a project needs a different license,
change `LICENSE`, `README.md`, `CONTRIBUTING.md`, and `CLA.md` together before
accepting outside contributions.

## Active vs optional workflows

Active workflows:

- `.github/workflows/repo-hygiene.yml` — common repository checks and dependency determinism.

Optional workflow templates:

- `templates/workflows/ci-node.yml`
- `templates/workflows/ci-rust.yml`

Copy one into `.github/workflows/ci.yml` after choosing the project stack.
