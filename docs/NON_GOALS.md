# PkgWarden non-goals

PkgWarden should stay focused on package-manager and dependency-ingestion
configuration hardening.

## Do not implement

- CVE lookup or vulnerability database maintenance.
- Package malware classification.
- Package reputation scoring.
- License compliance scanning.
- Full SBOM generation as a core feature.
- Runtime exploitability analysis.
- Secret scanning beyond package-manager config evidence needed for
  registry/token hardening.
- Broad GitHub repository hardening unrelated to dependency ingestion.

## Acceptable adjacent checks

PkgWarden may check CI and GitHub Actions only when the workflow affects
dependency installation, package-manager behavior, lockfile enforcement,
package firewall usage, or dependency-bot posture.

PkgWarden may warn about package-manager credentials in config files, but it
should not replace a general-purpose secret scanner.

PkgWarden may reference SCA and package firewall products in recommendations,
but should not compete with them.
