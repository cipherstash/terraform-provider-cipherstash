# terraform-provider-cipherstash

Terraform provider for CipherStash plus the public Go packages it uses. It is in development and not published to the Terraform Registry. `README.md` is the user documentation; keep it consistent with code changes.

## Layout

- `internal/provider`: the provider, its resources and data source, and the offline test suite. `main.go` serves it.
- `pkg/stack/auth` and `pkg/stack/manage`: public packages that other projects also import. `pkg/stack` has its own AGENTS.md.
- `docs/`: generated from the schema descriptions. Never edit it by hand.

## Toolchain and commands

`mise.toml` pins Go and Terraform and sets `GOWORK=off`; `mise.test.toml` adds golangci-lint, active only with `--env test`. Run commands through mise (`mise run <task>` or `mise exec -- <command>`) so the pinned tools apply.

| Command | Use |
| --- | --- |
| `mise run check` | Race-enabled offline tests, `go vet` and the gofmt check; the first CI job. Takes several minutes because the CLI tests run real `terraform` commands. |
| `mise run --env test lint` | golangci-lint; the second CI job. `mise exec --env test -- golangci-lint run --fix ./...` fixes most findings. |
| `mise exec -- go test ./internal/provider -run '^TestCLI' -count=1` | Only the Terraform CLI tests. Narrow `-run` further while iterating. |
| `mise run docs` | Regenerates `docs/`. |
| `mise run build` / `mise run install-local` | Builds the provider, or installs it into a local mirror under `.local/`. |

Never run `mise run test:acc` or set `TF_ACC=1` without explicit approval. Live acceptance tests create and destroy real actors and clients in a shared CipherStash workspace. Every other test is offline and needs no network access or secrets.

Lint is stricter than `check`: it formats with gofumpt rather than gofmt, requires blank lines after blocks and defers and before `return` (wsl_v5), and runs testifylint. In tests, use `require` for error assertions in the test body and `assert` inside HTTP handlers and other goroutines.

## Generated files

`docs/` comes from the `Description` strings in the schemas; change the Go descriptions, run `mise run docs` and commit the pages with the source change. `pkg/stack/internal/*/client.gen.go` comes from `go generate` (see `pkg/stack/AGENTS.md`). After running either generator, `git status` must show only the changes you intended; a clean tree is the drift check.

## Provider conventions

- `internal/provider` imports `pkg/stack/manage` as `control`. Resources call it only through the `controlClient` interface in `provider.go`; add any new manage operation there.
- Build diagnostic details from `operationError(err)` plus fixed operation context. Never put `err.Error()` from `manage` or `auth` into a diagnostic: upstream bodies can contain submitted secrets. Failure tests assert diagnostics never contain `fixture-upstream-secret`.
- Every attribute has a plain `Description` (no `MarkdownDescription`). Type names carry `cts_` or `zerokms_` for the owning service. Arguments the API cannot update use `RequiresReplace`, and Update returns a "provider bug" error.
- Mark credentials `Sensitive`: the resource attributes `access_key` and `client_key`, and the provider argument `client_access_key`. Resource secrets are still stored in state and saved plans, and provider inputs can appear in saved plans; keep the README and descriptions saying so.
- After a create, `defer created.Wipe()`, call `Export*` once, copy the bytes into the model and `clear` them.
- State rules:
  - Save the new identity and any secret with `resp.State.Set` right after the create call, before any follow-up read, so a failed readback cannot orphan the object.
  - Call `RemoveResource` only after a successful List shows the object absent; a failed read keeps state.
  - Refresh and import only read. Refresh keeps values the API cannot return (`access_key`, `token_expiry`, `client_key`, `keyset_id`).
  - Deleting an object that is already gone succeeds. Writes are never retried.
  - Create never adopts an existing object; the user imports it instead.
- Breaking changes (Terraform arguments, type names or exported Go identifiers) ship without compatibility aliases or state migration and are documented in the README.

## Tests

- `cli_test.go` runs Terraform against the in-process provider and fails unless `terraform` on `PATH` is exactly the pinned version. `crud_test.go`, `failures_test.go` and `provider_test.go` call the provider directly; `crud_test.go` holds the token-signing fake. `resources_test.go` injects client results through `testControl`, which embeds `controlClient`, so calling an unstubbed method (such as a write during refresh) panics.
- Direct tests build on `newServiceFixture(t)` with `fixtureClient(t, fixtureTransport(t, "admin", f.ServeHTTP))`. Inject failures with `f.faults` (a fault that never fires fails the test) and assert `f.mutations` is empty for refresh and import.
- Tests in `internal/provider` must not call `t.Parallel()`: they replace the process-wide `http.DefaultTransport`.
- When you change a write path, extend the failure and recovery cases in `failures_test.go`, `resources_test.go` and `cli_test.go`.

## Commits

Use Conventional Commits as in `git log`, with a scope where one applies (`fix(keyset): …`, `feat(stack): …`; `ci:` and `docs:` are unscoped). Breaking changes add `!` and a `BREAKING CHANGE:` footer with migration steps. The body explains why the change is needed and what it does.
