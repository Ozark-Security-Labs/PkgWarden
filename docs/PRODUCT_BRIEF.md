# Product Brief: PkgWarden

## One-liner

A defensive repository hardening advisor for package-manager and
dependency-ingestion configuration.

## Target users

- Security engineers rolling out package firewall or private registry
  controls.
- AppSec teams reviewing many repositories for dependency-ingestion
  posture.
- Development teams that want actionable package-manager config guidance.
- Platform engineers defining repository baseline policies.
- Open-source maintainers hardening dependency update and install behavior.

## Primary job to be done

When reviewing a repository, show exactly which package-manager,
dependency-bot, and CI install settings are weak, where they live in the
repository, and the concrete change required to harden them.

## Why now

Modern repositories pull from multiple package ecosystems, automate
dependency updates through bots, and install dependencies in CI. Each layer
has its own hardening surface: cooldowns, lockfile enforcement, registry
configuration, install-script controls, package firewall integration, and
credential handling. SCA scanners catch vulnerable dependencies after they
are pulled in. PkgWarden inspects the acquisition path itself.

## Differentiator

PkgWarden is not an SCA scanner. It does not maintain a vulnerability
database, score package risk, or detect malware. It is a configuration
inventory and evidence ledger for dependency-ingestion controls. This
creates a stable substrate for policy enforcement, profile-driven
hardening, and safe autofix.

## MVP success criteria

- Scans a representative Node or Python repository without running it.
- Lists discovered package managers, manifests, lockfiles, configs, and CI
  workflows.
- Flags missing cooldowns, registry bypass, unsafe install-script posture,
  missing lockfile enforcement, and plaintext credentials with file/line
  evidence.
- Produces a useful Markdown report in CI.
- Emits machine-readable JSON for downstream tools and SARIF for code
  scanning.

## Open design questions

- Should approved-registry posture default to a vendor-neutral profile or
  to a `socket-firewall` / `veracode-package-firewall` profile when the
  repository already opts in?
- How aggressive should autofix be for cooldown settings versus
  registry-routing changes (which often need org-specific URLs)?
- Should rule severity be fully data-driven, or should profiles select
  hand-tuned severity tables per ecosystem?
