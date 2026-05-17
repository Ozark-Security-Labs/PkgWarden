# Fixture Repositories

Fixture repositories live under `fixtures/` and are used by scanner tests to
exercise realistic repository layouts without executing fixture code.

## Add a Fixture

1. Create a small directory under `fixtures/` with only the files needed for the
   behavior under test.
2. Prefer minimal package-manager examples, such as a manifest plus the
   matching lockfile or policy file.
3. Add the fixture to the golden case list in
   `internal/scanner/fixture_harness_test.go`.
4. Run the scanner or the fixture tests and review the JSON output.
5. Regenerate goldens only after reviewing the output:

   ```bash
   UPDATE_GOLDENS=1 go test ./internal/scanner -run TestFixtureGoldenOutputs
   ```

6. Run the full validation suite:

   ```bash
   gofmt -l .
   go vet ./...
   go test ./...
   go build ./cmd/pkgwarden
   ```

Golden files live under `fixtures/golden/`. Normal `go test ./...` compares
scanner output to these files and never rewrites them unless
`UPDATE_GOLDENS=1` is explicitly set.

## Fixture Scope

Keep fixtures focused:

- Use `empty-repo` for zero-inventory behavior.
- Use single-package fixtures for one ecosystem and one expected rule outcome.
- Use monorepo or mixed-ecosystem fixtures only when cross-root behavior matters.
- Use malformed fixtures for warnings and parser/policy error handling.
- Do not include real credentials, real private registry URLs, or generated
  dependency trees.
