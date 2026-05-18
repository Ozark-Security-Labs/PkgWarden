# Roadmap

PkgWarden delivery is organized into eight milestones. The detailed issue
backlog (PW-001 through PW-058) is tracked in the
`Ozark-Security-Labs/PkgWarden` GitHub issues, which are the canonical
source of truth.

## M0: Project foundation and scanner core

Create the PkgWarden repo, CLI entrypoint, scanner data model, parser
abstraction, fixture harness, and initial reports. This milestone must land
before ecosystem-specific rules scale up.

## M1: Node.js package-manager hardening MVP

Implement npm, pnpm, Yarn, and Bun discovery, parsers, and hardening rules
for cooldowns, registries, lockfiles, install scripts, and exotic
dependency specs.

## M2: Python package-manager hardening MVP

Implement pip, uv, and Poetry discovery, parsers, and hardening rules for
package indexes, cooldown/exclude-newer controls, hashes, pinning,
lockfiles, and firewall posture.

## M3: Dependency bots, CI install validation, and firewall posture

Analyze Dependabot, Renovate, GitHub Actions install commands, and
vendor-neutral package firewall posture. Align bot cooldowns with
package-manager hardening.

## M4: Reporting, GitHub Action, and releasable v0.1

Ship production-friendly JSON, Markdown, SARIF, GitHub Action,
annotations, documentation, and release workflow for v0.1.

## M5: Safe autofix and policy profiles v0.2

Add conservative patch generation, profile-driven enforcement, policy
schema validation, and safe autofix for low-risk package-manager and bot
settings.

## M6: Additional ecosystems v0.3

Expand beyond Node and Python to JVM, .NET, Ruby, Rust, and Go
package-manager hardening controls.

## M7: Organization scale and plugin system v1.0

Add org-level policy bundles, optional vendor API adapters, plugin
interfaces, and large-scale rollout features.

## Recommended sequence

1. Finish M0 completely.
2. Implement Node and Python inventory and parsers in parallel.
3. Add cooldown, registry, lockfile, and install-script rules.
4. Add dependency-bot and CI validation.
5. Finish reporting, GitHub Action, docs, and release flow.
6. Add autofix and broader ecosystem support after v0.1.
