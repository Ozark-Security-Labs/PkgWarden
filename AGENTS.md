# Repository Guidelines

Guidance for coding agents working in this repository.

## Project Overview

PROJECT_NAME is PROJECT_DESCRIPTION.

## Safety and scope

- This repository is for defensive, authorized security work.
- Do not add exploit automation, payload generation, credential theft, or live-target attack behavior.
- Keep analysis local/offline by default unless the user explicitly opts in.
- Avoid executing analyzed repository code.
- Treat findings as evidence-bound hypotheses unless mechanically proven.

## Repository layout

Update this section after project creation.

Suggested layout:

- `src/` or `crates/`: implementation.
- `tests/` or `fixtures/`: regression and fixture tests.
- `docs/`: design and user documentation.
- `.github/`: workflows and community health files.

## Build, test, and development commands

Update this section with project-specific commands.

## Coding conventions

- Keep public behavior deterministic and test-covered.
- Add fixtures for scanner/rule behavior.
- Preserve advisory vs enforce mode boundaries.
- Keep output formats stable and documented.
- Prefer explicit evidence, spans, and reviewer questions over vague claims.

## Pull request expectations

- Explain the behavior change.
- Include tests/fixtures for analysis behavior.
- Update docs/changelog for user-facing changes.
- Confirm dependency and workflow changes are pinned deterministically.
