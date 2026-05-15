# Ozark Security Labs Repository Standards

## Required files

- `README.md`
- `LICENSE`
- `CLA.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `SUPPORT.md`
- `CODE_OF_CONDUCT.md`
- `CHANGELOG.md`
- `.github/pull_request_template.md`
- `.github/ISSUE_TEMPLATE/*`
- `.github/dependabot.yml`
- `.github/workflows/repo-hygiene.yml`
- `.deterministic-deps.yml`

## Security-tooling posture

Projects should be defensive, authorized, evidence-bound, and local-first by default.

## Dependency posture

- Pin GitHub Actions to full commit SHAs in enforceable repositories.
- Commit lockfiles for package ecosystems that support them.
- Prefer exact versions for direct dependencies.
- Use `deterministic-deps` in advisory mode first, then enforce mode once findings are baselined.

## Contribution posture

- Require CLA acceptance for non-trivial contributions.
- Keep issue templates specific enough to reproduce scanner behavior.
- Preserve a private vulnerability reporting path.
