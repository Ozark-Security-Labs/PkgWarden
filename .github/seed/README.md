# GitHub seed data

This directory contains the canonical source-of-truth for PkgWarden's
GitHub labels, milestones, and issues. The seed is applied by an
idempotent Python script and is intended to bootstrap a fresh repository
or backfill missing items in an existing one.

## Files

- `pkgwarden_seed.json` — canonical seed: 52 labels, 8 milestones, 58
  issues with bodies. Issue ids `PW-001` through `PW-058` are stable and
  should be referenced in commits and PRs.
- `ISSUES_INDEX.md` — human-readable index of all 58 issues with their
  milestone and labels.

## Applying the seed

The seeder is at [`scripts/seed_github.py`](../../scripts/seed_github.py).
It requires `gh` to be installed and authenticated with permission to
create labels, milestones, and issues on the target repository.

Always dry-run first:

```bash
python3 scripts/seed_github.py \
  --repo Ozark-Security-Labs/PkgWarden \
  --data .github/seed/pkgwarden_seed.json \
  --dry-run
```

Then apply for real:

```bash
python3 scripts/seed_github.py \
  --repo Ozark-Security-Labs/PkgWarden \
  --data .github/seed/pkgwarden_seed.json
```

The script:

- Creates labels via `gh label create` (or `gh label edit` if a label
  with the same name exists).
- Creates milestones via the REST API (or PATCHes existing ones with the
  same title).
- Creates issues via `gh issue create`, skipping any issue whose title
  already contains the same `PW-###` id.

Re-running the script is safe: it will not duplicate labels, milestones,
or issues.

## Selective re-runs

Skip stages with `--skip-labels`, `--skip-milestones`, or
`--skip-issues`. For example, to re-add only missing issues after
labels and milestones already exist:

```bash
python3 scripts/seed_github.py \
  --repo Ozark-Security-Labs/PkgWarden \
  --data .github/seed/pkgwarden_seed.json \
  --skip-labels --skip-milestones
```

## Updating the seed

The seed JSON is hand-edited. When you add or remove an issue:

1. Update `pkgwarden_seed.json` with the new issue object (`id`, `title`,
   `body`, `milestone`, `labels`).
2. Refresh `ISSUES_INDEX.md` so the human-readable index stays in sync.
3. Open a PR with both changes.
4. Re-run the seeder against the live repository after merge.

Existing issues are not edited by the seeder. To change an issue body or
metadata after creation, edit the issue directly on GitHub.
