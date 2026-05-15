# Contributing to PROJECT_NAME

Thanks for helping improve PROJECT_NAME.

## License

PROJECT_NAME is licensed under the GNU Affero General Public License version 3 only
(`AGPL-3.0-only`). By contributing, you agree that your contribution is submitted
under the PROJECT_NAME Contributor License Agreement in [CLA.md](CLA.md).

## Contributor License Agreement

All non-trivial contributions require CLA acceptance before merge. You can accept
the CLA by signing through an approved CLA workflow, or by confirming in your pull
request that you have read and agree to [CLA.md](CLA.md).

If you are contributing on behalf of an employer or another organization, make
sure you are authorized to submit the contribution under the CLA.

## Development

Document the project-specific setup here.

Suggested sections:

```bash
# install/build/test commands go here
```

## Security-tooling expectations

- Keep analysis local/offline by default unless the user explicitly opts in.
- Avoid executing analyzed repository code.
- Keep findings evidence-bound and avoid overstating confidence.
- Add fixtures/tests for false-positive and false-negative sensitive behavior.
- Keep advisory and enforce modes distinct when the project has CI behavior.
- Pin GitHub Actions and dependency declarations deterministically.

## Pull requests

Before opening a pull request:

- Run the relevant build and test commands.
- Update documentation and changelog entries for user-facing behavior.
- Include fixtures or reproduction cases for scanner/rule behavior changes.
- Call out known limitations and follow-up work.
