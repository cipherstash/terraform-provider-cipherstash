# terraform-provider-cipherstash

Terraform provider for CipherStash plus the public Go packages it uses. It is in development and not published to the Terraform Registry. `README.md` is the user documentation; keep it consistent with code changes.

## Layout

- `internal/provider`: the provider, its resources and data source, and the offline test suite. `main.go` serves it.
- `internal/eql`: the EQL v4 installers, compiled in from `bundles/<version>/eql-v4-install.sql` (byte-for-byte release assets, listed with their release tags and SHA-256 digests in `releases.json`, which a test checks). Until cipherstash/stack has a stable Go release, ship only the latest release candidate and the one before it: adding a release removes the oldest bundle and its manifest entry, and the SQL that inspects and installs them.
- `examples/`: complete Terraform configurations. `templates/guides/` holds the guides tfplugindocs renders into `docs/guides/`; a guide embeds an example with `{{ tffile "examples/<name>/main.tf" }}`.
- `pkg/stack/auth` and `pkg/stack/manage`: public packages that other projects also import. `pkg/stack` has its own AGENTS.md.
- `docs/`: generated from the schema descriptions. Never edit it by hand.

## Toolchain and commands

`mise.toml` pins Go and Terraform and sets `GOWORK=off`; `mise.test.toml` adds golangci-lint, active only with `--env test`. Run commands through mise (`mise run <task>` or `mise exec -- <command>`) so the pinned tools apply.

| Command | Use |
| --- | --- |
| `mise run check` | Race-enabled offline tests, `go vet` and the gofmt check; the first CI job. Takes several minutes because the CLI tests run real `terraform` commands. |
| `mise run --env test lint` | golangci-lint; the second CI job. `mise exec --env test -- golangci-lint run --fix ./...` fixes most findings. |
| `mise exec -- go test ./internal/provider -run '^TestCLI' -count=1` | Only the Terraform CLI tests. Narrow `-run` further while iterating. |
| `mise run test:postgres` | Tests named `*Postgres*` against the superuser URL in `CS_TEST_POSTGRES_URL`; the CI `postgres` job runs it on PostgreSQL 16 and 17. Each test creates and drops its own database and roles. It passes `-rapid.checks` and `-rapid.steps` to bound the upgrade state machine; running that test without them takes rapid's defaults of 100 traces of about 30 Terraform actions. |
| `mise run examples:validate` | `terraform validate` on each `examples/` directory using the local mirror; needs network access for other providers. `check` runs `terraform fmt -check` on `examples/`. |
| `mise run codegen` | Runs `go generate ./...`, which regenerates `docs/` and the API clients. |
| `mise run --env docs site` | Builds the Zensical site from `docs/` (tools in `mise.docs.toml`); the Docs workflow publishes it to `gh-pages` from `main`. |
| `mise run build` / `mise run install-local` | Builds the provider, or installs it into a local mirror under `.local/`. |

Never run `mise run test:acc` or set `TF_ACC=1` without explicit approval. Live acceptance tests create and destroy real actors and clients in a shared CipherStash workspace. Every other test is offline and needs no network access or secrets.

Lint is stricter than `check`: it formats with gofumpt rather than gofmt, requires blank lines after blocks and defers and before `return` (wsl_v5), and runs testifylint. In tests, use `require` for error assertions in the test body and `assert` inside HTTP handlers and other goroutines.

## Generated files

`mise run codegen` runs every `go:generate` directive. `docs/` comes from the `Description` strings in the schemas through the tfplugindocs directive in `main.go`; change the Go descriptions, run `mise run codegen` and commit the pages with the source change. `pkg/stack/internal/*/client.gen.go` comes from the oapi-codegen directives (see `pkg/stack/AGENTS.md`). After regenerating, `git status` must show only the changes you intended; CI's Generated files job fails on any drift.

## Provider conventions

- Resources call `pkg/stack/manage` only through the `manageClient` interface in `provider.go`; add any new manage operation there.
- Build diagnostic details from `operationError(err)` plus fixed operation context. Never put `err.Error()` from `manage` or `auth` into a diagnostic: upstream bodies can contain submitted secrets. Failure tests assert diagnostics never contain `fixture-upstream-secret`.
- Database failures use `databaseError(err)` the same way: it maps the SQLSTATE class to fixed text and never includes PostgreSQL's message or detail, which can quote submitted values. PostgreSQL notices go to `tflog`, never to diagnostics.
- The provider configuration has two optional halves, `auth` and `database`, each on only when present. Resources get them through `clientFromProviderData` or `databaseFromProviderData` and report a missing half with `providerDataError`. EQL resources call the database only through the `eqlDatabase` interface in `provider.go`.
- Every attribute has a plain `Description` (no `MarkdownDescription`). Type names carry `cts_`, `zerokms_` or `eql_` for the owning service or product. Arguments the API cannot update use `RequiresReplace`, and Update returns a "provider bug" error.
- Mark credentials `Sensitive`: the resource attributes `access_key` and `client_key`, and the provider argument `client_access_key`. Resource secrets are still stored in state and saved plans, and provider inputs can appear in saved plans; keep the README and descriptions saying so.
- After a create, `defer created.Wipe()`, call `Export*` once, copy the bytes into the model and `clear` them.
- State rules:
  - Save the new identity and any secret with `resp.State.Set` right after the create call, before any follow-up read, so a failed readback cannot orphan the object.
  - Call `RemoveResource` only after a successful List shows the object absent; a failed read keeps state.
  - Refresh and import only read. Refresh keeps values the API cannot return (`access_key`, `token_expiry`, `client_key`).
  - Deleting an object that is already gone succeeds. Writes are never retried.
  - Create never adopts an existing object; the user imports it instead.
- Breaking changes (Terraform arguments, type names or exported Go identifiers) ship without compatibility aliases or state migration and are documented in the README.

## Tests

- `cli_test.go` runs Terraform against the in-process provider and fails unless `terraform` on `PATH` is exactly the pinned version. `crud_test.go`, `failures_test.go` and `provider_test.go` call the provider directly; `crud_test.go` holds the token-signing fake. `resources_test.go` injects client results through `testManage`, which embeds `manageClient`, so calling an unstubbed method (such as a write during refresh) panics.
- Direct tests build on `newServiceFixture(t)` with `fixtureClient(t, fixtureTransport(t, "admin", f.ServeHTTP))`. Inject failures with `f.faults` (a fault that never fires fails the test) and assert `f.mutations` is empty for refresh and import.
- Tests in `internal/provider` must not call `t.Parallel()`: they replace the process-wide `http.DefaultTransport`.
- `resources_test.go` injects database results through `testEQL`. Tests that need a real database have `Postgres` in their name and skip without `CS_TEST_POSTGRES_URL`; clean up in `t.Cleanup` with `context.Background()`, because `t.Context()` is cancelled before cleanups run.
- When you change a write path, extend the failure and recovery cases in `failures_test.go`, `resources_test.go` and `cli_test.go`.

## Commits

Use Conventional Commits as in `git log`, with a scope where one applies (`fix(keyset): …`, `feat(stack): …`; `ci:` and `docs:` are unscoped). Breaking changes add `!` and a `BREAKING CHANGE:` footer with migration steps. The body explains why the change is needed and what it does.
