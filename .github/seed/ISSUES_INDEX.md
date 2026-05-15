# PkgWarden GitHub Issue Index

| ID | Title | Milestone | Labels |
|---|---|---|---|
| PW-001 | PW-001: Create repository scaffold, CLI entrypoint, and project conventions | M0: Project foundation and scanner core | priority:P0, type:chore, area:core, area:cli, size:M |
| PW-002 | PW-002: Define scanner data model for inventory, evidence, findings, rules, and profiles | M0: Project foundation and scanner core | priority:P0, type:feature, area:core, area:rules, area:policy, size:L |
| PW-003 | PW-003: Implement repository inventory walker | M0: Project foundation and scanner core | priority:P0, type:feature, area:core, area:parser, size:L |
| PW-004 | PW-004: Create parser abstraction and line-aware parse utilities | M0: Project foundation and scanner core | priority:P0, type:feature, area:parser, area:core, size:L |
| PW-005 | PW-005: Implement rule engine and baseline profile execution | M0: Project foundation and scanner core | priority:P0, type:feature, area:rules, area:policy, size:L |
| PW-006 | PW-006: Add fixture repository test harness | M0: Project foundation and scanner core | priority:P0, type:test, area:test-fixtures, area:core, size:M |
| PW-007 | PW-007: Implement human and JSON report output | M0: Project foundation and scanner core | priority:P0, type:feature, area:reporting, area:cli, size:M |
| PW-008 | PW-008: Add `.pkgwarden.yml` policy file support | M0: Project foundation and scanner core | priority:P1, type:feature, area:policy, area:core, size:M |
| PW-009 | PW-009: Add initial documentation skeleton and non-goals page | M0: Project foundation and scanner core | priority:P1, type:docs, area:docs, size:S, good-first-issue |
| PW-010 | PW-010: Add secret-redaction utility for package-manager evidence | M0: Project foundation and scanner core | priority:P0, type:feature, area:secrets, area:reporting, size:M |
| PW-011 | PW-011: Detect Node.js package managers, manifests, lockfiles, and workspaces | M1: Node.js package-manager hardening MVP | priority:P0, type:feature, area:node, area:parser, size:L |
| PW-012 | PW-012: Parse `.npmrc` and npm-related package config | M1: Node.js package-manager hardening MVP | priority:P0, type:feature, area:node, area:parser, size:M |
| PW-013 | PW-013: Implement npm cooldown and lockfile hardening rules | M1: Node.js package-manager hardening MVP | priority:P0, type:feature, area:node, area:cooldown, area:lockfiles, area:rules, size:M |
| PW-014 | PW-014: Parse `pnpm-workspace.yaml` and legacy pnpm config locations | M1: Node.js package-manager hardening MVP | priority:P0, type:feature, area:node, area:parser, size:M |
| PW-015 | PW-015: Implement pnpm cooldown, build-script, exotic dependency, and verification rules | M1: Node.js package-manager hardening MVP | priority:P0, type:feature, area:node, area:cooldown, area:install-scripts, area:lockfiles, area:rules, size:L |
| PW-016 | PW-016: Parse `.yarnrc.yml` and Yarn project metadata | M1: Node.js package-manager hardening MVP | priority:P0, type:feature, area:node, area:parser, size:M |
| PW-017 | PW-017: Implement Yarn cooldown, hardened mode, immutable install, script, and checksum rules | M1: Node.js package-manager hardening MVP | priority:P0, type:feature, area:node, area:cooldown, area:install-scripts, area:lockfiles, area:rules, size:L |
| PW-018 | PW-018: Parse Bun config and implement Bun hardening rules | M1: Node.js package-manager hardening MVP | priority:P1, type:feature, area:node, area:parser, area:cooldown, area:install-scripts, size:M |
| PW-019 | PW-019: Detect exotic and high-risk dependency specifiers in Node manifests | M1: Node.js package-manager hardening MVP | priority:P1, type:feature, area:node, area:registry, area:rules, size:M |
| PW-020 | PW-020: Implement Node registry, firewall, and private-registry posture checks | M1: Node.js package-manager hardening MVP | priority:P0, type:feature, area:node, area:registry, area:firewall, vendor:socket, vendor:veracode, profile:private-registry, size:L |
| PW-021 | PW-021: Detect Python package managers, manifests, lockfiles, and config files | M2: Python package-manager hardening MVP | priority:P0, type:feature, area:python, area:parser, size:L |
| PW-022 | PW-022: Parse pip config, requirements, and constraints files | M2: Python package-manager hardening MVP | priority:P0, type:feature, area:python, area:parser, size:L |
| PW-023 | PW-023: Implement pip dependency-confusion, hash, and pinning rules | M2: Python package-manager hardening MVP | priority:P0, type:feature, area:python, area:registry, area:lockfiles, area:rules, size:L |
| PW-024 | PW-024: Parse uv configuration and implement uv cooldown/lockfile rules | M2: Python package-manager hardening MVP | priority:P0, type:feature, area:python, area:parser, area:cooldown, area:lockfiles, size:M |
| PW-025 | PW-025: Parse Poetry config and implement Poetry source/cooldown/lockfile rules | M2: Python package-manager hardening MVP | priority:P1, type:feature, area:python, area:parser, area:cooldown, area:registry, area:lockfiles, size:L |
| PW-026 | PW-026: Implement Python registry, firewall, and private-index posture checks | M2: Python package-manager hardening MVP | priority:P0, type:feature, area:python, area:registry, area:firewall, vendor:socket, vendor:veracode, profile:private-registry, size:L |
| PW-027 | PW-027: Implement Python production requirements classification | M2: Python package-manager hardening MVP | priority:P1, type:feature, area:python, area:policy, area:rules, size:M |
| PW-028 | PW-028: Parse Dependabot configuration and implement cooldown rules | M3: Dependency bots, CI install validation, and firewall posture | priority:P0, type:feature, area:dependency-bots, area:cooldown, area:parser, size:M |
| PW-029 | PW-029: Parse Renovate configuration and implement minimum-release-age rules | M3: Dependency bots, CI install validation, and firewall posture | priority:P0, type:feature, area:dependency-bots, area:cooldown, area:parser, size:L |
| PW-030 | PW-030: Parse GitHub Actions workflows for package-manager install commands | M3: Dependency bots, CI install validation, and firewall posture | priority:P0, type:feature, area:ci, area:github-action, area:parser, size:L |
| PW-031 | PW-031: Implement CI locked-install validation rules | M3: Dependency bots, CI install validation, and firewall posture | priority:P0, type:feature, area:ci, area:lockfiles, area:rules, size:L |
| PW-032 | PW-032: Implement firewall posture summary and vendor-neutral evidence model | M3: Dependency bots, CI install validation, and firewall posture | priority:P0, type:feature, area:firewall, area:registry, vendor:socket, vendor:veracode, size:M |
| PW-033 | PW-033: Implement token and plaintext registry hardening rules | M3: Dependency bots, CI install validation, and firewall posture | priority:P1, type:feature, area:secrets, area:registry, area:rules, size:M |
| PW-034 | PW-034: Generate Markdown report suitable for PR comments | M3: Dependency bots, CI install validation, and firewall posture | priority:P1, type:feature, area:reporting, area:github-action, size:M |
| PW-035 | PW-035: Implement SARIF output for GitHub code scanning | M4: Reporting, GitHub Action, and releaseable v0.1 | priority:P0, type:feature, area:reporting, size:L |
| PW-036 | PW-036: Create GitHub Action wrapper | M4: Reporting, GitHub Action, and releaseable v0.1 | priority:P0, type:feature, area:github-action, area:ci, size:L |
| PW-037 | PW-037: Add GitHub Actions annotations output | M4: Reporting, GitHub Action, and releaseable v0.1 | priority:P1, type:feature, area:reporting, area:github-action, size:M |
| PW-038 | PW-038: Create public MVP rule catalog documentation | M4: Reporting, GitHub Action, and releaseable v0.1 | priority:P0, type:docs, area:docs, area:rules, size:L |
| PW-039 | PW-039: Add release workflow, versioning, and binary distribution | M4: Reporting, GitHub Action, and releaseable v0.1 | priority:P0, type:chore, area:ci, area:cli, size:M |
| PW-040 | PW-040: Build v0.1 end-to-end demo fixtures and smoke tests | M4: Reporting, GitHub Action, and releaseable v0.1 | priority:P0, type:test, area:test-fixtures, area:ci, size:L |
| PW-041 | PW-041: Publish v0.1 launch README and quickstart | M4: Reporting, GitHub Action, and releaseable v0.1 | priority:P1, type:docs, area:docs, size:M |
| PW-042 | PW-042: Implement patch/diff model for safe autofix | M5: Safe autofix and policy profiles v0.2 | priority:P0, type:feature, area:autofix, area:core, size:L |
| PW-043 | PW-043: Add safe autofix for npm cooldown and lockfile config | M5: Safe autofix and policy profiles v0.2 | priority:P1, type:feature, area:autofix, area:node, area:cooldown, size:M |
| PW-044 | PW-044: Add safe autofix for pnpm, Yarn, and Bun cooldown settings | M5: Safe autofix and policy profiles v0.2 | priority:P1, type:feature, area:autofix, area:node, area:cooldown, size:L |
| PW-045 | PW-045: Add safe autofix for Dependabot and Renovate cooldowns | M5: Safe autofix and policy profiles v0.2 | priority:P1, type:feature, area:autofix, area:dependency-bots, area:cooldown, size:L |
| PW-046 | PW-046: Define and validate policy profiles | M5: Safe autofix and policy profiles v0.2 | priority:P0, type:feature, area:policy, area:rules, size:L |
| PW-047 | PW-047: Implement config precedence resolver | M5: Safe autofix and policy profiles v0.2 | priority:P1, type:feature, area:policy, area:core, size:M |
| PW-048 | PW-048: Add Maven and Gradle hardening support | M6: Additional ecosystems v0.3 | priority:P2, type:feature, area:ecosystem-jvm, area:registry, area:lockfiles, size:XL |
| PW-049 | PW-049: Add NuGet hardening support | M6: Additional ecosystems v0.3 | priority:P2, type:feature, area:ecosystem-dotnet, area:registry, area:lockfiles, size:L |
| PW-050 | PW-050: Add Bundler/RubyGems hardening support | M6: Additional ecosystems v0.3 | priority:P2, type:feature, area:ecosystem-ruby, area:registry, area:lockfiles, size:L |
| PW-051 | PW-051: Add Cargo hardening support | M6: Additional ecosystems v0.3 | priority:P2, type:feature, area:ecosystem-rust, area:registry, area:lockfiles, size:L |
| PW-052 | PW-052: Add Go modules hardening support | M6: Additional ecosystems v0.3 | priority:P2, type:feature, area:ecosystem-go, area:registry, area:lockfiles, size:L |
| PW-053 | PW-053: Design plugin interface for custom rules and parsers | M7: Organization scale and plugin system v1.0 | priority:P2, type:spike, area:integrations, area:rules, size:L |
| PW-054 | PW-054: Spike Socket Firewall API adapter | M7: Organization scale and plugin system v1.0 | priority:P2, type:spike, area:integrations, area:firewall, vendor:socket, size:M |
| PW-055 | PW-055: Spike Veracode Package Firewall API adapter | M7: Organization scale and plugin system v1.0 | priority:P2, type:spike, area:integrations, area:firewall, vendor:veracode, size:M |
| PW-056 | PW-056: Add org-level policy bundles and baseline export | M7: Organization scale and plugin system v1.0 | priority:P2, type:feature, area:policy, area:integrations, size:L |
| PW-057 | PW-057: Create contributor onboarding and maintainer workflow | M7: Organization scale and plugin system v1.0 | priority:P2, type:docs, area:docs, size:M |
| PW-058 | PW-058: Create governance and trademark/name usage note for PkgWarden | M7: Organization scale and plugin system v1.0 | priority:P3, type:docs, area:docs, size:S, status:needs-decision |
