# Terraform provider for CipherStash

Use this provider to manage machine identities, ZeroKMS clients, keysets, and keyset grants in a CipherStash workspace. You can also look up an existing client without managing it. The provider handles Terraform configuration and state; this repository's native `internal/stack/auth` and `internal/stack/manage` packages handle authentication and service requests.

**This provider is in development and is not published to the Terraform Registry.** Local builds use `terraform.local/cipherstash/cipherstash` at version `0.0.1`. A clean checkout builds with the pinned Go toolchain and module dependencies; no sibling SDK checkout, Go workspace, Rust toolchain or WebAssembly authentication guest is required. See [Distribution and licensing](#distribution-and-licensing) before distributing source or binaries.

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

Set `crn` to the workspace's [CipherStash Resource Name (CRN)](https://cipherstash.com/docs/reference/workspace/configuration), in the format `crn:<region>.aws:<workspace ID>`. The CRN identifies both the workspace and its region. The provider does not discover a workspace or read one from a saved profile or environment variable.

Use an access key with the Admin role for the provider's administration operations. Create this credential outside the Terraform configuration that uses it: the provider cannot safely manage its own authentication credential. See the [provider reference](docs/index.md) for the credential arguments.

```hcl
provider "cipherstash" {
  crn = var.crn
  # Supply an Admin access key through CIPHERSTASH_ACCESS_KEY.
}
```

Supply the key securely through `CIPHERSTASH_ACCESS_KEY` or the sensitive `access_key` argument. An omitted or null argument uses the environment variable. An empty string or a value that is unknown during provider configuration is an error, not a request to use the environment. These are the provider's credentials, not the application's `CS_CLIENT_*` configuration.

Native authentication verifies each exchanged token's RS256 signature against the CipherStash Token Service (CTS) signing keys, issuer, audience, expiry, workspace and Admin role. It also validates the advertised ZeroKMS endpoint before use. Each provider instance owns its token cache and authentication lifetime; reconfiguration and shutdown cancel token refresh. CTS and ZeroKMS still authorize each service request. Successful provider configuration does not prove that a later administration request will be permitted. Use the narrower Member or Control roles for application workloads where appropriate; the provider's Admin requirement does not mean your application needs Admin.

### Protect state and credentials

Terraform marks returned access keys and client key values as sensitive, but **stores resource secrets in state and saved plans**. Sensitive marking hides values in normal display; it does not encrypt them or prevent JSON/raw outputs from revealing them. Sensitive provider inputs can also appear in saved plans. Reading the provider's access key from the environment is not the same as storing a resource's returned key in state.

Use an encrypted state backend with restricted access. Protect backups and saved plans, and never commit credentials, state, or plan files. The provider does not display upstream error bodies, which can contain submitted data. The provider clears exported creation-secret buffers, but Terraform still holds string copies.

## Choose what Terraform manages

| Resource or data source | What it manages | Change behavior |
| --- | --- | --- |
| [`cipherstash_actor`](docs/resources/actor.md) | A machine identity and its access key | Any argument change replaces the actor and creates a new key. |
| [`cipherstash_client`](docs/resources/client.md) | A ZeroKMS client and its client key | Any argument change replaces the client. Existing grants are not transferred to the replacement. |
| [`cipherstash_keyset`](docs/resources/keyset.md) | A keyset's name, description, and enabled status | Updates the existing keyset. Destroy disables it; it does not delete key material. |
| [`cipherstash_keyset_grant`](docs/resources/keyset_grant.md) | One client/keyset grant | Changing either ID replaces the grant. Destroy revokes only that pair. |
| [`cipherstash_client` data source](docs/data-sources/client.md) | Read-only client metadata | Does not import, change, or delete the client or its grants. |

Give each managed object one owner. For example, Terraform can manage a shared application keyset while a provisioning worker manages tenant keysets. Do not let the worker and Terraform manage the same keyset or grant pair. This provider has no workspace or human-membership resources.

### Manage client access

A new ZeroKMS client receives a grant to the workspace's default keyset. The client resource records that keyset in its computed `keyset_id`; you cannot configure that argument. It leaves additional grants unchanged during refresh, including grants created by a provisioning worker.

Use `cipherstash_keyset_grant` to manage an additional grant. It manages one `(client_id, keyset_id)` pair, not the client's entire grant list. Import an existing pair rather than creating it again: creation refuses to silently adopt a grant. Import checks that the pair exists without changing service state.

Do not separately manage the grant tracked by a `cipherstash_client` resource, whether it is the default grant or one selected during import. The client resource requires that grant to remain present. If it disappears, refresh reports an error and keeps the client in state. Restore the grant outside Terraform or deliberately replace the client.

Replacing a client creates a different identity. Grants associated with the old client are not transferred to it. Plan credential and grant changes separately; consider `lifecycle { prevent_destroy = true }` for an established client. This provider does not implement an application cutover or prove that deleting a client physically removes every grant record on the service.

### Read an existing client

Use the client data source when you need metadata without taking ownership:

```hcl
data "cipherstash_client" "api" {
  id = "11111111-1111-4111-8111-111111111111" # Replace with your existing client ID.
}
```

The lookup returns the client's `name`, `description`, and all granted `keyset_ids`, including disabled keysets. No grants produces an empty set; a missing client or failed lookup produces an error. The lookup does not select a keyset or retrieve the client key value. Keep existing secrets in your secret store. Removing the data source does not delete the client.

## Understand lifecycle and recovery

### Replace an actor or client

Changing any actor or client argument requires replacement and creates a new credential. An actor's `token_expiry` sets the lifetime of tokens issued from its access key, not the lifetime of the key itself. If omitted, CTS uses 900 seconds. The API does not return this setting, so Terraform cannot detect changes made outside Terraform.

Actor and client deletion accept a successful service response or an already-absent response; the provider does not then check inventory. Separate live checks observed removal from inventory, but that is not proof of immediate credential revocation. In a disposable development workspace, a deleted actor's key still succeeded in a new token exchange after the actor and its key disappeared from listings. The revocation delay is unknown. Before a security-sensitive credential change, verify when the old credential and already-issued tokens stop working.

### Import existing objects

Import brings an existing object under Terraform management; it does not recover a secret returned only at creation.

| Resource | Import ID | What import cannot do |
| --- | --- | --- |
| Actor | Actor ID, such as `app-JBSWY3DPEHPK3PXP` | Recover `access_key` or `token_expiry`; both are null after import. Setting a token lifetime afterward can require replacement. |
| Client | Client UUID when exactly one grant exists; otherwise `client UUID/keyset UUID` | Recover `client_key`, choose among several grants, or create a missing grant. The selected grant must exist. A client with no grants cannot be imported. |
| Keyset | Keyset UUID | Delete key material or select the workspace default. Import includes disabled keysets; set `enabled = false` to keep one disabled. |
| Grant | `client UUID/keyset UUID` | Create the pair or change other grants. |

The example IDs are placeholders. To keep an imported actor or client, use its previously saved credential from your secret store. To obtain a new credential, replace the resource and plan the change for its consumers.

### Disable or stop managing a keyset

`cipherstash_keyset` creates a keyset without a client or grant and never exports its key material. Name, description, and enabled-status changes update the same keyset without rotating key material. The metadata and enabled-status requests are separate operations, not a transaction. Terraform records successful steps and the values returned by a follow-up read, including after a failed write.

Destroy disables the keyset, confirms that it is disabled or absent, and removes it from state. The keyset and key material remain in CipherStash. An already-disabled keyset needs no write. A failed disable, failed follow-up read, or still-enabled result returns an error and retains state. Disabling can interrupt every client using the keyset, including clients with worker-managed grants; the grants themselves remain.

Import does not enable a disabled keyset, but configuration defaults `enabled` to `true`. Set `enabled = false` to keep it disabled. A new keyset is always created enabled; `enabled = false` is applied afterward, with the returned ID saved first. If that request fails, inspect state and the next plan before retrying. To manage a keyset again after destroy, import its retained ID. The provider does not automatically adopt an existing keyset by name.

Use `lifecycle { prevent_destroy = true }` to reject a destroy plan while the resource block remains configured. It does not prevent an in-place `enabled = false` update, and it stops protecting the resource if you remove the entire block. To stop managing a keyset without disabling it, use Terraform's `removed` block with `lifecycle { destroy = false }` rather than a normal destroy.

### Recover from a failed apply

A failed apply does not mean nothing was created. The provider saves returned IDs and secrets before additional metadata reads. When a later step fails, Terraform can keep the resource in state and mark it tainted, meaning a later plan may replace it. Inspect service inventory, Terraform state, and the next plan before retrying.

If a create request succeeds but its response is lost, the provider may never receive the new object's ID. Writes are not automatically retried. Inspect inventory and import an existing object before retrying a conflicting create.

Refresh removes absent resources from state only after a successful lookup. Authentication or listing errors are not evidence of absence. An actor with missing or ambiguous access-key metadata stays in state with an error. Existing creation secrets are retained during refresh.

A grant's ID is known before the request because it is the client/keyset pair. After attempting creation, the provider saves that pair before reading it back. A failed write remains an error, and the pair stays in state unless a follow-up read confirms it is absent. A failed revoke counts as complete only if a follow-up read confirms absence; Terraform reports a warning about the failed request. No write is retried automatically.

### Live verification limits

**Keyset and grant lifecycles have not been verified against the live service.** Local fixture tests are not proof that these operations work live. Earlier Admin and Control grant/revoke and re-grant probes returned HTTP 500 with the existing default grant unchanged. Live keyset tests need separate approval because this provider cannot delete the resulting keyset.

### Preserve existing configuration

The repository's example configurations have been removed. If you used them, preserve your configuration and state until you have planned a migration. Do not apply an emptied root against retained state: Terraform would plan to destroy the resources it no longer sees in configuration.

## Develop and verify locally

Install [mise](https://mise.jdx.dev/). `mise.toml` pins Go 1.26.10 and Terraform 1.14.6 and sets `GOWORK=off`, so builds and tests use only this repository's module dependencies.

```sh
mise trust
mise install
mise run check
mise run install-local
export TF_CLI_CONFIG_FILE="$PWD/.local/terraform.rc"
```

These commands check and install the provider locally without creating CipherStash resources. Use your own Terraform root with the local provider address and version above. To plan against a workspace, supply its Admin access key securely through `CIPHERSTASH_ACCESS_KEY`; do not put the key in shell history or committed variable files. Review the plan and coordinate shared-workspace access before any apply.

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

The offline suite has three layers:

| Layer | What it establishes |
| --- | --- |
| Terraform CLI (`cli_test.go`) | Real Terraform 1.14.6 plans, applies, persisted imports, refresh, replacement and destroy through the protocol server. Checks dependent resources and lookups, sensitive secrets, grant ownership, external drift and validation. Failed-create and create-before-destroy cases inspect the next plan's saved identities and secrets, including deposed objects, then recover and check for orphans. |
| Direct native-backed tests (`failures_test.go`, `crud_test.go`, `provider_test.go`) | State retention on failed inventory reads, pagination and metadata ambiguity, partial keyset writes, uncertain grant/revoke outcomes, confirmed destroy, credential precedence, independent authentication lifetimes and cancellation. Native authentication verifies signed fixture tokens against local signing-key and HTTP fixtures; upstream error bodies must not enter diagnostics. |
| Direct resource tests (`resources_test.go`) | Focused reconciliation tests with injected control-client results, including import restrictions, missing objects and partial failures. |

CLI tests use `resource.UnitTest`, so they run without live-acceptance opt-in. They require the pinned Terraform on `PATH` and fail rather than download another version. Run them through mise, which supplies the actual executable rather than a tool shim. Each case uses a temporary CLI configuration and fake credentials. The in-process provider's transport only permits local fixture routing. Tests run serially because they replace the process-default transport and environment. This setup tests separate provider session ownership directly, not Terraform provider aliases or binary installation.

The shared service fixture models inventory and HTTP faults, not Terraform plans or state. Unexpected endpoints, malformed requests, handler panics and unused fault injections fail tests independently of provider diagnostics. Default tests clear `TF_ACC`: plugin-testing treats any nonempty value, including `0`, as opt-in.

Run just the CLI layer with `mise exec -- go test ./internal/provider -run '^TestCLI' -count=1 -v`. These tests need only this checkout and the pinned tools. They establish neither live permissions nor live keyset/grant lifecycle behavior, and do not resolve licensing.

Separate live checks verified that client creation without a specified keyset grants the default keyset, and that deleted clients disappear from inventory. Unique actor names returning 409 remain a fixture assumption, not recorded live proof. Removing a client from the fixture makes its grants unobservable; this does not prove deletion of grant records on the service. Real Admin and Control re-grant probes returned 500 with the default grant unchanged.

### Run approved live acceptance tests

Live actor/client tests use `terraform-plugin-testing`. Coordinate access to the shared workspace and explicitly set `TF_ACC=1`, `TF_ACC_WORKSPACE_ID`, a matching `TF_ACC_CRN`, and `CIPHERSTASH_ACCESS_KEY`. Then run `mise run test:acc`.

There is no default acceptance workspace. The task refuses to run without opt-in, and the test rejects a missing workspace ID, mismatched CRN, or missing credential before opening authentication. It creates uniquely named `tf-acc-*` actors and clients, checks refresh/import/replacement, destroys them, and compares actor, access-key, and client IDs against the initial inventory. It does not separately mutate keysets or grants.

## Distribution and licensing

Public source visibility does not grant a provider license, and this repository does not assert one. The provider no longer embeds the external SDK's WebAssembly authentication guest. This change does not establish licensing or redistribution rights for the provider or its dependencies.

Release automation, signing and publication are outside this development build workflow. Do not publish provider binaries or Terraform Registry artifacts based on this repository's visibility.
