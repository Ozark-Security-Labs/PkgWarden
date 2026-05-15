# Data Handling

PkgWarden is local-first. It scans bytes already in the repository under
test and writes reports the user has requested. It does not call external
services for the default scan and never modifies analyzed repository code.

## What PkgWarden reads

- Package manifests (`package.json`, `pyproject.toml`, `requirements.txt`,
  and equivalents).
- Lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`,
  `bun.lockb`, `uv.lock`, `poetry.lock`).
- Package-manager configuration (`.npmrc`, `.yarnrc.yml`, `pip.conf`,
  `bunfig.toml`).
- Dependency-bot configuration (`.github/dependabot.yml`, Renovate
  configuration in supported locations).
- GitHub Actions workflow files under `.github/workflows/`.
- `.pkgwarden.yml` policy.

Files outside this set are ignored. PkgWarden never executes any scanned
file.

## Secret redaction

PkgWarden detects and redacts token-shaped values in every output format,
including:

- `_authToken`, `_auth`, and `_password` entries in `.npmrc`.
- `username` / `password` URL components in registry URLs.
- API-token-shaped strings near credential keys in `pip.conf`,
  `.yarnrc.yml`, and `bunfig.toml`.

Redaction replaces the value with `***REDACTED***` and notes the redaction
in the evidence object so reviewers can see that a value was present
without learning the value itself. PkgWarden never includes a redacted
value in its own outputs.

Secret-shaped values that appear inside scan diagnostics are also
redacted. PkgWarden does not log raw file contents.

## Report sensitivity

Even after redaction, PkgWarden reports can contain:

- Registry hostnames (internal and external).
- Approved-registry policy and firewall posture.
- Repository structure (which package managers and CI workflows exist).
- Configuration values that imply organizational practices.

Treat reports as review material. They are appropriate for security
reviewers and the originating engineering team. They are usually not
appropriate to share with third parties without redaction.

## CI artifacts

The PkgWarden GitHub Action uploads the requested report formats as a
workflow artifact by default. CI artifacts inherit GitHub's artifact
retention and access controls. Configure retention and access on the
action invocation when reports should not persist beyond a workflow run.

SARIF upload is opt-in and requires `security-events: write`. SARIF
results appear in the repository's code-scanning tab and are visible to
users with code-scanning read access.

## No telemetry

PkgWarden does not phone home. It does not collect usage statistics,
report hashes to a remote service, or send findings to any third party.
Profile-driven Socket and Veracode checks examine repository evidence; they
do not contact the vendor APIs unless an explicit API integration is
implemented and enabled later (M7).

## Network access

The default scan is offline. A scan can opt in to remote validation for
specific rules using a future `--remote-validation` flag (tracked in M7
spikes). When remote validation runs, PkgWarden logs every outbound URL it
contacts in the diagnostics section of the report.

## Defensive-use boundary

PkgWarden is for analyzing repositories you own or are authorized to
review. It does not include attack tooling, exploit automation, or
bypass instructions. See [SECURITY.md](../SECURITY.md) for the full
authorized-use boundary.

<!-- TODO: expand once remote-validation and autofix-apply flows land. -->
