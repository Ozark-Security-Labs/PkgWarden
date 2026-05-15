# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state — read this first

This repo is in a **pre-implementation** state. It was generated from the Ozark Security Labs template, then seeded with the canonical PkgWarden GitHub backlog (52 labels, 8 milestones, issues `PW-001`..`PW-058`) on the current branch `chore/seed-github-backlog`. No PkgWarden source code has landed yet — `PW-001` itself is "Create repository scaffold, CLI entrypoint, and project conventions." Do not invent Go module paths, build commands, or test commands; if you need them and the scaffolding hasn't landed, say so.

Several template files still contain `PROJECT_NAME` / `PROJECT_DESCRIPTION` placeholders (notably `AGENTS.md`, `CONTRIBUTING.md`, `CHANGELOG.md`). The substitution tool is `scripts/apply-template.py` — run it when the user authorizes finalizing the template, not before:

```bash
python3 scripts/apply-template.py \
  --name "PkgWarden" \
  --slug pkgwarden \
  --description "Repository scanner for package-manager and dependency-ingestion hardening gaps" \
  --language go
```

## Mission and explicit non-goals

PkgWarden is a defensive, evidence-bound scanner that analyzes repository manifests, lockfiles, package-manager config, dependency-bot config, and CI workflows for ingestion-hardening gaps (cooldowns, lockfile/frozen-install posture, install-script controls, registry/firewall configuration, dependency-confusion exposure, CI install-command validation, plaintext credentials).

**PkgWarden is not an SCA product.** Do not add: CVE database lookups, package reputation scoring, malware detection, vulnerability prioritization, license compliance scanning, SBOM generation as a primary feature, or exploitability analysis.

## Authoritative design context (lives outside the repo)

The canonical design spec is at `/home/bcorder/Downloads/pkgwarden_handoff/`. Consult before architectural decisions:

- `AGENT_HANDOFF.md` — mission, MVP boundary, CLI contract, product defaults.
- `PROJECT_SPEC.md` — full product specification.
- `ARCHITECTURE.md` — scanner/parser/rule-engine/reporter layering.
- `ROADMAP_MILESTONES.md` — M0–M7 scope.
- `RULE_CATALOG_MVP.md` — v0.1 rule definitions.
- `docs/NON_GOALS.md` — explicit out-of-scope items.
- `docs/EXTERNAL_RESEARCH_REFERENCES.md` — sourcing notes for rules.

In-repo source of truth for the backlog: `.github/seed/pkgwarden_seed.json` and `.github/seed/ISSUES_INDEX.md`.

## Issue ID convention

All work tracks to issue IDs `PW-001..PW-058`. Reference the ID in branch names, commit messages, and PR descriptions. When editing the seed, **update `pkgwarden_seed.json` and `ISSUES_INDEX.md` together** — they are paired and a divergence will confuse future seeding runs.

To apply the seed to a fresh GitHub repo (requires `gh` auth + label/milestone/issue create permission):

```bash
python3 scripts/seed_github.py --repo OWNER/REPO --data .github/seed/pkgwarden_seed.json --dry-run
python3 scripts/seed_github.py --repo OWNER/REPO --data .github/seed/pkgwarden_seed.json
```

## CI and dependency posture

Active workflow: `.github/workflows/repo-hygiene.yml` — runs on PR and push to `main`, with two checks:

1. Whitespace via `git diff --check`.
2. `Ozark-Security-Labs/deterministic-deps` in **advisory** mode (severity-threshold `low`, SARIF off so the template works without GitHub Advanced Security).

Configuration for deterministic-deps lives in `.deterministic-deps.yml`. Pin all GitHub Actions to full commit SHAs; preserve advisory/enforce mode boundaries when adjusting it.

Optional templates under `templates/workflows/` (`ci-node.yml`, `ci-rust.yml`, `scorecard.yml`) ship with the Ozark template — **ignore the Node and Rust ones; PkgWarden is Go.** A Go CI workflow will be added under `PW-001` / `PW-039`.

## Product defaults to honor when implementing rules

From the handoff (do not change without an explicit user decision):

- Baseline cooldown: **7 days**. Strict cooldown: **14 days**.
- Findings carry evidence file path + line span where the parser can produce one.
- Token-like values must be redacted before they reach any output format.
- `--fix` defaults to dry-run; applying changes requires explicit `--apply`.
- Default scans must not require network access; `remote-validation` and vendor profiles (Socket, Veracode) are opt-in.
- Do not invent registry, firewall, or vendor URLs.

CLI contract (planned): `pkgwarden scan <path> [--profile baseline|strict|socket-firewall|veracode-package-firewall] [--format human|json|markdown|sarif] [--fail-on <severity>] [--policy .pkgwarden.yml] [--fix --dry-run|--apply]`.

## Coding posture

See `AGENTS.md` for the canonical safety, evidence-bound, local-first, and advisory-vs-enforce guidance. See `docs/repository-standards.md` for the Ozark Security Labs required-files baseline. Implementation guidance from the handoff: build the scanner core before package-manager rules; make parsers line-aware so findings are actionable; every rule needs at least one passing and one failing fixture; implement JSON output early and treat it as the contract for SARIF conversion; keep vendor profiles optional and explicit.

## Contribution mechanics

- Non-trivial contributions require CLA acceptance — see `CLA.md`.
- `main` is protected via `.github/rulesets/main-protection.json`; work on feature branches and open PRs.
- License is `AGPL-3.0-only`. Changes to license posture require touching `LICENSE`, `README.md`, `CONTRIBUTING.md`, and `CLA.md` together.
