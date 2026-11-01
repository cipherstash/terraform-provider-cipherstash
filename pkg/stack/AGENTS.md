# pkg/stack

Other projects import or vendor `auth` and `manage`, so every exported identifier is public API. Avoid changing one unless asked; when you do, update the README's "Go authentication and management packages" section.

## Boundaries

- `auth` and `manage` are the only public packages. Generated clients, test helpers and the User-Agent stay under `pkg/stack/internal`.
- Never import Terraform, `internal/provider` or any BNDRY module from here.
- Neither package reads environment variables, profile files or other ambient configuration (apart from proxy settings through the default transport). `manage.Config` only declares `go-envconfig` tags; the caller loads it.

## Security invariants

Keep these when changing the code. Most have tests in `auth/*_test.go` and `manage/client_test.go`; the 10-second timeout and response-body clearing do not.

- Access keys and creation results implement `fmt.Formatter` and print a redacted placeholder for every verb.
- Errors never contain response bodies or credentials. Errors from `NewTokenSource`, `Token`, `ZeroKMSURL`, `NewClient` and every `Client` method wrap a sentinel category (`ErrConfig`, `ErrAuthentication`, `ErrTransport`, `ErrResponse`, plus `manage`'s `ErrForbidden`, `ErrNotFound`, `ErrConflict`, `ErrSecretConsumed`) so callers branch with `errors.Is`. `ParseCRN` and `Parse*AccessKey` return uncategorised validation errors that never echo the input.
- `HTTPError` carries only the service name and status code. Its mapping of 401, 403, 404 and 409 to sentinels drives provider behaviour (`ErrNotFound` means already deleted), so changing it changes the provider.
- Requests are never retried and never follow redirects, and each has a 10-second timeout. A failed create may still have succeeded; doc comments tell callers to reconcile with the matching List call.
- Secrets returned once at creation are exported once (`Export*`, then `ErrSecretConsumed`, shared across copies) or cleared with `Wipe`. Clear response bodies that contain secrets with `defer clear(resp.Body)`.
- `auth` verifies each token's RS256 signature, issuer, audience, expiry, workspace, the role the key type requires, and the advertised ZeroKMS endpoint. It fetches signing keys on every exchange so a rotated key works immediately; do not add a signing-key cache.
- Every request sends `useragent.Value`. CTS rejects Go's default User-Agent.
- `NewTokenSource` and `NewClient` validate locally and make no network request. The caller owns the token source and its lifetime context.

## Generated clients

`internal/cts` and `internal/zerokms` each hold a vendor OpenAPI spec (`openapi.yaml`), an overlay (`overlay.yaml`), an oapi-codegen config (`oapi-codegen.yaml`) and the generated `client.gen.go`.

- Never edit `client.gen.go` or `openapi.yaml` by hand. The spec stays exactly as CipherStash publishes it; local changes go in `overlay.yaml`, and generator options, including the `include-operation-ids` allowlist, go in `oapi-codegen.yaml`.
- Regenerate with `mise exec -- go generate ./pkg/stack/...`. oapi-codegen is a Go `tool` dependency in `go.mod`.
- `manage/types.go` aliases generated types into the public API, so changes to `overlay.yaml` or `oapi-codegen.yaml` (names, fields, pointer choices, `name-normalizer`) are public API changes.

## Tests

- Tests run offline against local TLS servers. `internal/ctstest` is a fake CTS built on the generated server: it signs tokens with a test key, can rotate it, and rejects requests without the expected User-Agent. The ZeroKMS fake lives in `manage/client_test.go`.
- `mise exec -- go test -race ./pkg/stack/... -count=1` runs these packages in seconds.
