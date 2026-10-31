# Terraform provider for CipherStash

Use this provider to manage machine identities, ZeroKMS clients, keysets, and keyset grants in a CipherStash workspace. You can also look up an existing client without managing it. The provider handles Terraform configuration and state; this repository's `pkg/stack/auth` and `pkg/stack/manage` packages handle authentication and service requests.

**This provider is in development and is not published to the Terraform Registry.** Local builds use `terraform.local/cipherstash/cipherstash` at version `0.0.1`. No BNDRY module, sibling SDK checkout, local module replacement, Rust toolchain or WebAssembly authentication guest is required. See [Distribution and licensing](#distribution-and-licensing) before distributing source or binaries.

The SDK names distinguish CTS authentication identities (`CTSActor`, `CreateCTSActor`, `ListCTSActors`) from ZeroKMS encryption identities and permissions (`ZeroKMSClient`, `ZeroKMSKeyset`, `CreateZeroKMSClient`, `GrantZeroKMSKeyset`). Options and creation results use matching names. The administrative `manage.Client`, credential export methods, environment variables and wire formats are unchanged. The old SDK API names have no compatibility aliases.

## Go authentication and management packages

Go applications can import `github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/auth` and `github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/manage`. The Terraform provider uses these same packages. Generated CTS and ZeroKMS clients and test helpers remain private under `pkg/stack/internal`. Neither public package depends on BNDRY or Terraform. The management package preserves the reviewed service-qualified API and inventory validation from BNDRY's copy.

Use `ParseCRN`, a role-specific access-key parser (`ParseControlAccessKey`, `ParseAdminAccessKey` or `ParseMemberAccessKey`), and `NewTokenSource` to construct an `oauth2.TokenSource`. Construction validates configuration locally; calling `Token` exchanges the credential and verifies the signed token. Pass an owner-lifetime context and cancel it at shutdown. Tokens are cached until one minute before expiry; cancellation prevents further exchanges but does not invalidate a cached token. `ZeroKMSURL` returns the verified service endpoint from the token. The package does not choose environment variables or read credentials automatically.

Pass that CRN and token source to `manage.NewClient`. It makes no network request during construction and does not take ownership of the token source. Operations use their caller's context and the verified token's ZeroKMS endpoint, with no automatic write retries. `ListCTSActors` returns one page; follow `NextCursor` until empty. ZeroKMS inventories are unpaginated; use `ShowDisabled: true` when disabled keysets must remain visible. A malformed inventory is an error, not an empty list. Creation results export credentials once; clear the returned bytes after persisting them, or call `Wipe` if they will not be exported. Both packages use the repository's `terraform-provider-cipherstash/` User-Agent rather than BNDRY's `bndry/` identity.

`manage.Config[K auth.AccessKey]` binds `WorkspaceCRN` to `CS_WORKSPACE_CRN` and `ClientAccessKey` to `CS_CLIENT_ACCESS_KEY`, both required by `go-envconfig`. These are the same environment names as the Terraform provider. Select a concrete `auth.ControlAccessKey`, `auth.AdminAccessKey` or `auth.MemberAccessKey` type for `K`; decoding checks syntax, while signed-token verification enforces that type's role policy. For example, `envconfig.Process(ctx, &cfg)` can populate a `manage.Config[auth.AdminAccessKey]`; pass `cfg.WorkspaceCRN` and `cfg.ClientAccessKey` to `auth.NewTokenSource`. The struct does not load the environment, construct a client or grant access automatically.

This replaces the old `CRN`, `ControlAccessKey` and `ClientID` fields. There is no `CS_CONTROL_ACCESS_KEY` fallback; application client IDs belong in consumer configuration rather than shared management credentials. Applications migrating from BNDRY must change both auth and manage imports together and pin a revision containing both packages; no compatibility aliases to BNDRY types are provided. BNDRY's existing worker configuration is not changed here.

## Before you start

A [workspace](https://cipherstash.com/docs/reference/workspace) is CipherStash's unit of isolation. It contains clients, keysets, access keys, and configuration. These terms describe different parts of your setup:

| Term | Purpose |
| --- | --- |
| [Access key](https://cipherstash.com/docs/reference/auth/access-keys) | Authenticates requests to CipherStash services. Its role controls service-level permissions. It is not an encryption key. |
| Actor | A machine identity for an application (`app`) or agent (`agent`), with an access key. This provider resource is separate from a human workspace member. |
| [ZeroKMS client](https://cipherstash.com/docs/reference/auth/clients) | A registered application client with a client ID and client key. It is not the encryption-client object you construct in an SDK. |
| Client key value | The secret application-held part of CipherStash's split key architecture. Keep it separate from the client ID and access key. |
| [Keyset](https://cipherstash.com/docs/concepts/key-management) | An independent authority-key scope. Clients need a grant to use it. |
| Keyset grant | Permission for one client to use one keyset. A grant does not select the keyset in your application's SDK configuration. |

The linked CipherStash documentation explains the product concepts. This repository documents the Terraform-specific configuration, lifecycle, and limitations.

## Configure the provider

Set `workspace_crn` or `CS_WORKSPACE_CRN` to the workspace's [CipherStash Resource Name (CRN)](https://cipherstash.com/docs/reference/workspace/configuration), in the format `crn:<region>.aws:<workspace ID>`. The CRN identifies both the workspace and its region. The provider does not discover a workspace or read a saved profile.

Use a Control access key for management operations. Admin keys are also accepted, and the CTS API contract requires Admin for actor creation; a Control-only key does not promise access to every resource operation. Create this credential outside the Terraform configuration that uses it: the provider cannot safely manage its own authentication credential. See the [provider reference](docs/index.md) for the credential arguments.

```hcl
provider "cipherstash" {
  workspace_crn = var.workspace_crn
  # Supply the credential through CS_CLIENT_ACCESS_KEY.
  # Use an Admin key if this root creates actors.
}
```

Supply the key securely through `CS_CLIENT_ACCESS_KEY` or the sensitive `client_access_key` argument. For both `workspace_crn` and `client_access_key`, an omitted or null argument uses its environment variable. Explicit known values override the environment. Empty, unknown or malformed selected values fail without falling back to another source. Member-only credentials are rejected even though the environment variable is named `CS_CLIENT_ACCESS_KEY`.

This is a breaking configuration change: replace the provider's `crn` argument with `workspace_crn`, and `access_key` or `control_access_key` with `client_access_key`. Replace `CIPHERSTASH_ACCESS_KEY` or `CS_CONTROL_ACCESS_KEY` with `CS_CLIENT_ACCESS_KEY`. Old arguments are rejected and old environment names are ignored; there are no compatibility aliases. The actor resource's computed `access_key` and all client/keyset resource arguments are unchanged. The provider argument rename alone does not change resource state.

`CS_CLIENT_ID` identifies an application encryption client, not an authentication principal. Neither `manage.Config` nor the provider requires or reads it, and neither automatically grants that client access. Use `cipherstash_zerokms_keyset_grant` to manage explicit pairs. Application client keys remain separate from provider authentication.

Native authentication verifies each exchanged token's RS256 signature against the CipherStash Token Service (CTS) signing keys, issuer, audience, expiry, workspace and Control or Admin role. It also validates the advertised ZeroKMS endpoint before use. Each provider instance owns its token cache and authentication lifetime; reconfiguration and shutdown cancel token refresh. CTS and ZeroKMS still authorize each service request. Successful provider configuration does not prove that a later administration request will be permitted. Use the narrower Member or Control roles for application workloads where appropriate; actor creation's Admin requirement does not mean your application needs Admin.

### Protect state and credentials

Terraform marks returned access keys and client key values as sensitive, but **stores resource secrets in state and saved plans**. Sensitive marking hides values in normal display; it does not encrypt them or prevent JSON/raw outputs from revealing them. Sensitive provider inputs can also appear in saved plans. Reading the provider's access key from the environment is not the same as storing a resource's returned key in state.

Use an encrypted state backend with restricted access. Protect backups and saved plans, and never commit credentials, state, or plan files. The provider does not display upstream error bodies, which can contain submitted data. The provider clears exported creation-secret buffers, but Terraform still holds string copies.

## Choose what Terraform manages

Names identify the owning service: `cts` means CipherStash Token Service, which manages actors and their authentication access keys; `zerokms` identifies encryption clients, keysets and grants. An actor's `access_key` and a ZeroKMS client's `client_key` are different credentials.

| Resource or data source | What it manages | Change behavior |
| --- | --- | --- |
| [`cipherstash_cts_actor`](docs/resources/cts_actor.md) | A machine identity and its access key | Any argument change replaces the actor and creates a new key. |
| [`cipherstash_zerokms_client`](docs/resources/zerokms_client.md) | A ZeroKMS client and its client key | Name/description changes replace the client; grants are not transferred. UUID-bound key seeding only updates Terraform state. |
| [`cipherstash_zerokms_keyset`](docs/resources/zerokms_keyset.md) | A keyset's name, description, and enabled status | Updates the existing keyset. Destroy disables it; it does not delete key material. |
| [`cipherstash_zerokms_keyset_grant`](docs/resources/zerokms_keyset_grant.md) | One client/keyset grant | Changing either ID replaces the grant. Destroy revokes only that pair. |
| [`cipherstash_zerokms_client` data source](docs/data-sources/zerokms_client.md) | Read-only client metadata | Does not import, change, or delete the client or its grants. |

These names replace the earlier development types `cipherstash_actor`, `cipherstash_client`, `cipherstash_keyset` and `cipherstash_keyset_grant`. The old names are not registered, and there is no automatic cross-type state migration. If existing state uses the old types, retain the previous provider binary and protected state backups until you have planned a migration. Changing HCL type names alone does not migrate state. Import cannot recover creation-only credentials.

Give each managed object one owner. For example, Terraform can manage a shared application keyset while a provisioning worker manages tenant keysets. Do not let the worker and Terraform manage the same keyset or grant pair. This provider has no workspace or human-membership resources.

### Manage client access

A new ZeroKMS client receives a grant to the workspace's default keyset. The client resource manages identity, not grants. Its deprecated, computed `keyset_id` records historical creation or import metadata, not current access; you cannot configure that argument. Refresh preserves this value and the client key even if the historical grant disappears or the client has no grants.

Use `cipherstash_zerokms_keyset_grant` to manage any grant explicitly, including the automatic default grant. It manages one `(client_id, keyset_id)` pair, not the client's entire grant list. Import an existing pair rather than creating it again: creation refuses to silently adopt a grant. Grant import checks that the pair exists without changing service state.

Client refresh and import never add, restore or revoke grants. Use the existing `cipherstash_zerokms_client` data source's `keyset_ids` to read current grant inventory. Do not use the resource's historical `keyset_id` to determine whether access is currently granted.

Replacing a client creates a different identity. Grants associated with the old client are not transferred to it. Plan credential and grant changes separately; consider `lifecycle { prevent_destroy = true }` for an established client. This provider does not implement an application cutover or prove that deleting a client physically removes every grant record on the service.

### Read an existing client

Use the client data source when you need metadata without taking ownership:

```hcl
data "cipherstash_zerokms_client" "api" {
  id = "11111111-1111-4111-8111-111111111111" # Replace with your existing client ID.
}
```

The lookup returns the client's `name`, `description`, and all granted `keyset_ids`, including disabled keysets. No grants produces an empty set; a missing client or failed lookup produces an error. The lookup does not select a keyset or retrieve the client key value. Keep existing secrets in your secret store. Removing the data source does not delete the client.

## Understand lifecycle and recovery

### Replace an actor or client

Changing any actor argument, or a client's name or description, requires replacement and creates a new credential. Client metadata updates are not supported by the published ZeroKMS API. An actor's `token_expiry` sets the lifetime of tokens issued from its access key, not the lifetime of the key itself. If omitted, CTS uses 900 seconds. The API does not return this setting, so Terraform cannot detect changes made outside Terraform.

Actor and client deletion accept a successful service response or an already-absent response; the provider does not then check inventory. Separate live checks observed removal from inventory, but that is not proof of immediate credential revocation. In a disposable development workspace, a deleted actor's key still succeeded in a new token exchange after the actor and its key disappeared from listings. The revocation delay is unknown. Before a security-sensitive credential change, verify when the old credential and already-issued tokens stop working.

### Import existing objects

Import brings an existing object under Terraform management; it does not recover a secret returned only at creation.

| Resource | Import ID | What import cannot do |
| --- | --- | --- |
| Actor | Actor ID, such as `app-JBSWY3DPEHPK3PXP` | Recover `access_key` or `token_expiry`; both are null after import. Setting a token lifetime afterward can require replacement. |
| Client | Client UUID, with zero, one or many grants; legacy `client UUID/keyset UUID` is also accepted | Recover `client_key` or change grants. UUID-only imports leave `keyset_id` null. Legacy pair imports record the second UUID as historical metadata only, even if that grant no longer exists. |
| Keyset | Keyset UUID | Delete key material or select the workspace default. Import includes disabled keysets; set `enabled = false` to keep one disabled. |
| Grant | `client UUID/keyset UUID` | Create the pair or change other grants. |

The example IDs are placeholders. To keep an imported actor or client, use its previously saved credential from your secret store. To obtain a new credential, replace the resource and plan the change for its consumers.

The client ID, client key and computed string `keyset_id` retain their attribute representations; the resource type rename is a separate breaking change as described above. Within the current resource type, refresh preserves historical `keyset_id` values, while new UUID-only imports do not select a grant. A legacy pair import validates both UUIDs and the client's existence, but does not validate the keyset or grant. Import the pair separately as a `cipherstash_zerokms_keyset_grant` if Terraform should own that permission.

### Record an existing client key after import

Import first without seed arguments. To record a key you already hold, subsequently configure both `client_key` and `client_key_client_id`, then review and apply the state-only update:

```hcl
variable "existing_client_key" {
  type      = string
  sensitive = true
}

resource "cipherstash_zerokms_client" "api" {
  name                 = "existing-name"
  description          = "existing-description"
  client_key_client_id = "11111111-1111-4111-8111-111111111111" # The UUID you imported.
  client_key           = var.existing_client_key
}
```

Supply the secret through your protected variable mechanism, not an import ID or committed file. The key must be a generated v1 CBOR permutation keyset encoded as standard base64 or mixed-case hex, without whitespace. The supplied string is preserved exactly, not normalized. This is not a raw 32-byte key: [recipher 0.3.1](https://docs.rs/crate/recipher/0.3.1/source/src/keyset/proxy_keyset.rs) serializes four named fields (`p1`, `p2_from`, `p2_to`, `p3`), each containing a `permutation` integer array. Validation requires permutations of 0–15 for the first three and 0–32 for the last, and rejects duplicate fields and trailing data. Field order and total encoded length are not fixed; unknown fields are ignored. This supports the generated named-map format, not every alternate representation accepted by Rust's permissive deserializer.

Both inputs must be known during planning, and the explicit UUID must match the managed client. Do not derive the expected UUID from this resource's own `id`: that would defeat the protection against reusing configuration for another import. This check verifies the operator's declared pairing, not cryptographic ownership. Verify key/client correspondence separately with your application; refresh performs no encryption or decryption.

Seeding does not write to CipherStash, rotate a credential, change metadata or manage grants. An already-persisted key can only be retained, not replaced by another supplied value. Refresh, removing the seed arguments and setting them to null retain the stored key. Removing `client_key_client_id` may itself produce a state-only update. A missing remote client or failed inventory read prevents adoption, including when applying a previously saved adoption plan. A null key is not proof of import provenance: failed creation-secret export can also leave one.

Creation and replacement are rejected during planning while either seed argument is configured, including taint and `-replace` with either replacement order. For intentional replacement, remove both seed arguments and review the resulting credential/grant changes. The new client receives its own new key, never the seed. These checks do not prevent intentional destroy; use `prevent_destroy` when appropriate.

Terraform's `ignore_changes` has its normal semantics. An ignored key change retains the stored value instead of adopting or rejecting the ignored input. Ignoring a null imported key will not seed it. UUID assertions are checked against Terraform's effective configuration too; do not ignore a UUID change if you intend the provider to evaluate it. Keys remain in state and saved plans despite sensitive marking.

### Disable or stop managing a keyset

`cipherstash_zerokms_keyset` creates a keyset without a client or grant and never exports its key material. Name, description, and enabled-status changes update the same keyset without rotating key material. The metadata and enabled-status requests are separate operations, not a transaction. Terraform records successful steps and the values returned by a follow-up read, including after a failed write.

CipherStash rejects metadata updates while a keyset is disabled. When a plan enables a disabled keyset and changes metadata, the provider enables it first. When a plan changes metadata and disables an enabled keyset, it updates metadata first. An already-disabled keyset must have `enabled = true` planned to change its metadata; the provider never temporarily enables a keyset configured to remain disabled. If enabling succeeds but the metadata update fails, the keyset remains enabled and Terraform retains that partial success.

Destroy disables the keyset, confirms that it is disabled or absent, and removes it from state. The keyset and key material remain in CipherStash. An already-disabled keyset needs no write. A failed disable, failed follow-up read, or still-enabled result returns an error and retains state. Disabling can interrupt every client using the keyset, including clients with worker-managed grants; the grants themselves remain.

Import does not enable a disabled keyset, but configuration defaults `enabled` to `true`. Set `enabled = false` to keep it disabled. A new keyset is always created enabled; `enabled = false` is applied afterward, with the returned ID saved first. If that request fails, inspect state and the next plan before retrying. To manage a keyset again after destroy, import its retained ID. The provider does not automatically adopt an existing keyset by name.

Use `lifecycle { prevent_destroy = true }` to reject a destroy plan while the resource block remains configured. It does not prevent an in-place `enabled = false` update, and it stops protecting the resource if you remove the entire block. To stop managing a keyset without disabling it, use Terraform's `removed` block with `lifecycle { destroy = false }` rather than a normal destroy.

### Recover from a failed apply

A failed apply does not mean nothing was created. The provider saves returned IDs and secrets before additional metadata reads. When a later step fails, Terraform can keep the resource in state and mark it tainted, meaning a later plan may replace it. Inspect service inventory, Terraform state, and the next plan before retrying.

If a create request succeeds but its response is lost, the provider may never receive the new object's ID. Writes are not automatically retried. Inspect inventory and import an existing object before retrying a conflicting create.

Refresh removes absent resources from state only after a successful lookup. Authentication or listing errors are not evidence of absence. Client and keyset inventories with invalid UUIDs or repeated identity fields, or client entries with missing/null descriptions, fail refresh without changing saved state. An empty description and an empty grant array remain valid. An actor with missing or ambiguous access-key metadata stays in state with an error. Existing creation secrets are retained during refresh.

A grant's ID is known before the request because it is the client/keyset pair. After attempting creation, the provider saves that pair before reading it back. A failed write remains an error, and the pair stays in state unless a follow-up read confirms it is absent. A failed revoke counts as complete only if a follow-up read confirms absence; Terraform reports a warning about the failed request. No write is retried automatically.

### Live verification limits

**Live API probes are not full Terraform keyset/grant lifecycle verification.** On 2026-10-30, isolated Development probes created, enabled and disabled a test keyset, and successfully added and revoked an additional grant while the client's creation/default grant remained. Revoking the creation/default grant while another grant remained returned HTTP 500. Revoking a final grant to a non-workspace-default keyset also returned HTTP 500; that keyset was the client's creation keyset. Inventory confirmed both failed revocations left the grants present. The cause remains unresolved; these observations do not establish that all revokes fail or that removing only the last grant is the problem. No provider workaround is justified by this evidence.

Those probes deleted their test clients and preserved existing resources. Test keyset `9fc1fcf6-da8a-4b8f-abdc-aae2405d6651` remains disabled because keysets cannot be deleted. Do not rely on creation-grant removal as part of an automated lifecycle until the failure is resolved. Exercise the actual Terraform keyset/grant lifecycle before production use; the successful API probes do not replace that check.

Before the BNDRY migration, on 2026-10-30, the native-backed actor/client acceptance test passed creation, refresh, UUID and legacy-pair imports, replacement and deletion in workspace `2JTSJCX24VP2WCBC`. Actor, access-key and client IDs matched the pre-test baseline afterward. A subsequent direct `internal/stack` client test verified Admin authentication, client creation, metadata and grant inventory, filtering, one-time key export and deletion. Go and the published Rust protocol decoder accepted the live inventories, including scalar and array grant representations. Complete client/keyset inventories matched that run's baseline afterward: two clients and nine keysets, eight disabled. No new lasting resource was created by that run.

The BNDRY-backed provider repeated the actor/client Terraform acceptance test on 2026-10-30 in Development workspace `2JTSJCX24VP2WCBC`, using a temporary module replacement for the local inventory-hardening fix. Creation, refresh, UUID and legacy-pair imports, replacement and deletion passed; actor, access-key and client IDs matched the baseline afterward. This run did not repeat the keyset/grant lifecycle or validate a published dependency containing that fix.

Live zero-grant inventory representation remains unverified. Offline Terraform CLI tests cover zero-grant import and refresh; accepting an empty array in a fixture is not live evidence. None of these checks establishes immediate credential invalidation after deletion; see the actor-key observation above. Client-key seeding checks format and the asserted UUID, not cryptographic key/client correspondence.

### Preserve existing configuration

The repository's example configurations have been removed. If you used them, preserve your configuration and state until you have planned a migration. Do not apply an emptied root against retained state: Terraform would plan to destroy the resources it no longer sees in configuration.

## Develop and verify locally

Install [mise](https://mise.jdx.dev/). `mise.toml` pins Go 1.27.3 and Terraform 1.14.6 and sets `GOWORK=off`, so builds and tests use only this repository's module dependencies. All dependencies are public, and `go.mod` has no module replacements. A standalone checkout needs no access to BNDRY or a sibling SDK checkout.

```sh
mise trust
mise install
mise run check
mise run install-local
export TF_CLI_CONFIG_FILE="$PWD/.local/terraform.rc"
```

These commands check and install the provider locally without creating CipherStash resources. Use your own Terraform root with the local provider address and version above. To plan against a workspace, supply its Control or Admin access key securely through `CS_CLIENT_ACCESS_KEY`; do not put the key in shell history or committed variable files. Review the plan and coordinate shared-workspace access before any apply.

A lockfile generated from the local mirror describes your local build, not a published provider. After rebuilding changed source, refresh that root's provider checksum with `terraform providers lock -fs-mirror=<provider checkout>/.local/mirror terraform.local/cipherstash/cipherstash` before initializing again. Do not use this development-version process for a production lockfile.

### Run local checks

| Command | What it does |
| --- | --- |
| `mise run check` | Runs race-enabled tests, Go vet, and Go formatting checks without changing tracked files or contacting live services. |
| `mise run test` | Runs offline Terraform CLI and fixture tests with `TF_ACC` cleared, even if acceptance is enabled in your shell. The race detector needs a C toolchain. |
| `mise run build` | Builds the local provider binary. |
| `mise run docs` | Generates reference pages from Go schema descriptions using tfplugindocs 0.25.0. Edit those descriptions, not `docs/` directly. |
| `mise run --env test lint` | Runs optional golangci-lint 2.14.0 from `mise.test.toml`. It is separate from `check`. |

Documentation generation and live acceptance are not part of `check`. This repository does not configure Rust, guest builds, or local services, and does not force `CGO_ENABLED=0`.

### Understand test coverage

The offline suite has four layers:

| Layer | What it establishes |
| --- | --- |
| Terraform CLI (`cli_test.go`) | Real Terraform 1.14.6 plans, applies, persisted imports, refresh, replacement and destroy through the protocol server. Checks dependent resources and lookups, sensitive secrets, grant ownership, external drift and validation. Failed-create and create-before-destroy cases inspect the next plan's saved identities and secrets, including deposed objects, then recover and check for orphans. |
| Direct native-backed tests (`failures_test.go`, `crud_test.go`, `provider_test.go`) | State retention on failed inventory reads, pagination and metadata ambiguity, partial keyset writes, uncertain grant/revoke outcomes, confirmed destroy, credential precedence, independent authentication lifetimes and cancellation. Native authentication verifies signed fixture tokens against local signing-key and HTTP fixtures; upstream error bodies must not enter diagnostics. |
| Direct resource tests (`resources_test.go`) | Focused reconciliation tests with injected control-client results, including import restrictions, missing objects and partial failures. |
| Public SDK (`pkg/stack/auth`, `pkg/stack/manage`) | Signed-token validation and refresh, service request contracts, malformed-inventory rejection, zero-grant clients, one-time secret export, cancellation, and no write retries or redirects. These tests use local service fixtures, not live credentials. |

CLI tests use `resource.UnitTest`, so they run without live-acceptance opt-in. They require the pinned Terraform on `PATH` and fail rather than download another version. Run them through mise, which supplies the actual executable rather than a tool shim. Each case uses a temporary CLI configuration and fake credentials. The in-process provider's transport only permits local fixture routing. Tests run serially because they replace the process-default transport and environment. This setup tests separate provider session ownership directly, not Terraform provider aliases or binary installation.

The shared service fixture models inventory and HTTP faults, not Terraform plans or state. Unexpected endpoints, malformed requests, handler panics and unused fault injections fail tests independently of provider diagnostics. Default tests clear `TF_ACC`: plugin-testing treats any nonempty value, including `0`, as opt-in.

Run just the CLI layer with `mise exec -- go test ./internal/provider -run '^TestCLI' -count=1 -v`. These tests need only this checkout and the pinned tools. They establish neither live permissions nor live keyset/grant lifecycle behavior, and do not resolve licensing.

Separate live checks verified that client creation without a specified keyset grants the default keyset, and that deleted clients disappear from inventory. Unique actor names returning 409 remain a fixture assumption, not recorded live proof. Removing a client from the fixture makes its grants unobservable; this does not prove deletion of grant records on the service. Real Admin and Control re-grant probes returned 500 with the default grant unchanged.

### Run approved live acceptance tests

Live actor/client tests use `terraform-plugin-testing`. Coordinate access to the shared workspace and explicitly set `TF_ACC=1`, `TF_ACC_WORKSPACE_ID`, a matching `TF_ACC_CRN`, and `CS_CLIENT_ACCESS_KEY` containing an Admin key for actor creation. Then run `mise run test:acc`.

There is no default acceptance workspace. The task refuses to run without opt-in, and the test rejects a missing workspace ID, mismatched CRN, or missing credential before opening authentication. It creates uniquely named `tf-acc-*` actors and clients, checks refresh/import/replacement, destroys them, and compares actor, access-key, and client IDs against the initial inventory. It does not separately mutate keysets or grants.

## Distribution and licensing

Public source visibility does not grant a provider license, and this repository does not assert one. The provider no longer embeds the external SDK's WebAssembly authentication guest. This change does not establish licensing or redistribution rights for the provider or its dependencies.

Release automation, signing and publication are outside this development build workflow. Do not publish provider binaries or Terraform Registry artifacts based on this repository's visibility.
