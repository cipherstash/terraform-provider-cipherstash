# Terraform provider for CipherStash

Use this provider to manage machine identities, ZeroKMS clients, keysets, and keyset grants in a CipherStash workspace, and to install EQL v4 into PostgreSQL databases. You can also look up an existing client without managing it. The guide [Prepare CipherStash and PostgreSQL for encrypted data with Terraform](docs/guides/eql-quickstart.md) walks through both. The provider handles Terraform configuration and state; this repository's `pkg/stack/auth` and `pkg/stack/manage` packages handle authentication and service requests.

**This provider is in development and is not published to the Terraform Registry.** Local builds use `terraform.local/cipherstash/cipherstash` at version `0.0.1`. No BNDRY module, sibling SDK checkout, local module replacement, Rust toolchain or WebAssembly authentication guest is required. See [Distribution and licensing](#distribution-and-licensing) before distributing source or binaries.

The SDK names distinguish CTS authentication identities (`CTSActor`, `CreateCTSActor`, `ListCTSActors`) from ZeroKMS encryption identities and permissions (`ZeroKMSClient`, `ZeroKMSKeyset`, `CreateZeroKMSClient`, `GrantZeroKMSKeyset`). Options and creation results use matching names. The administrative `manage.Client`, credential export methods, environment variables and wire formats are unchanged. The old SDK API names have no compatibility aliases.

## Go authentication and management packages

Go applications can import `github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/auth` and `github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/manage`. The Terraform provider uses these same packages. Generated CTS and ZeroKMS clients and test helpers remain private under `pkg/stack/internal`. Neither public package depends on BNDRY or Terraform. The management package preserves the reviewed service-qualified API and inventory validation from BNDRY's copy.

Use `ParseCRN`, a role-specific access-key parser (`ParseControlAccessKey`, `ParseAdminAccessKey` or `ParseMemberAccessKey`), and `NewTokenSource` to construct an `oauth2.TokenSource`. `auth.WithCTSURL` and `manage.WithCTSURL` replace the workspace region's CTS URL; pass the same URL to both. The token source then also expects that URL as the token issuer and fetches signing keys from it. Construction validates configuration locally; calling `Token` exchanges the credential and verifies the signed token. Pass an owner-lifetime context and cancel it at shutdown. Tokens are cached until one minute before expiry; cancellation prevents further exchanges but does not invalidate a cached token. `ZeroKMSURL` returns the verified service endpoint from the token. The package does not choose environment variables or read credentials automatically.

Pass that CRN and token source to `manage.NewClient`. It makes no network request during construction and does not take ownership of the token source. Operations use their caller's context and the verified token's ZeroKMS endpoint, with no automatic write retries. `ListCTSActors` returns one page; follow `NextCursor` until empty. ZeroKMS inventories are unpaginated; use `ShowDisabled: true` when disabled keysets must remain visible. A malformed inventory is an error, not an empty list. Creation results export credentials once; clear the returned bytes after persisting them, or call `Wipe` if they will not be exported. Both packages use the repository's `terraform-provider-cipherstash/` User-Agent rather than BNDRY's `bndry/` identity.

`manage.Config[K auth.AccessKey]` binds `WorkspaceCRN` to `CS_WORKSPACE_CRN` and `ClientAccessKey` to `CS_CLIENT_ACCESS_KEY`, both required by `go-envconfig`. These are the same environment names as the Terraform provider. Select a concrete `auth.ControlAccessKey`, `auth.AdminAccessKey` or `auth.MemberAccessKey` type for `K`; decoding checks syntax, while signed-token verification enforces that type's role policy. For example, `envconfig.Process(ctx, &cfg)` can populate a `manage.Config[auth.AdminAccessKey]`; pass `cfg.WorkspaceCRN` and `cfg.ClientAccessKey` to `auth.NewTokenSource`. The struct does not load the environment, construct a client or grant access automatically.

The Terraform provider decodes its selected argument/environment values into `manage.Config[auth.AdminAccessKey]`. Terraform handles omitted, null and unknown arguments before shared decoding, preserving the precedence rules below. Provider authentication requires a verified Admin role; the shared SDK's Control and Member policies remain available to other consumers.

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

The provider block has two optional nested attributes, and each half of the provider is on only when its attribute is present:

- `auth` connects to a CipherStash workspace. Every `cts` and `zerokms` resource and data source requires it. Without it, the provider never reads `CS_*` environment variables and never contacts CipherStash.
- `database` connects to a PostgreSQL server. `cipherstash_eql_v4` requires it. Without it, the provider never opens a database connection.

A resource whose half is missing fails with "Provider auth settings required" or "Provider database settings required". A root that only installs EQL needs no CipherStash credentials, and a root that only manages workspace objects needs no database.

### Connect to CipherStash

Set `auth.workspace_crn` or `CS_WORKSPACE_CRN` to the workspace's [CipherStash Resource Name (CRN)](https://cipherstash.com/docs/reference/workspace/configuration), in the format `crn:<region>.aws:<workspace ID>`. The CRN identifies both the workspace and its region. The provider does not discover a workspace or read a saved profile.

Use an Admin access key. Every `auth` configuration requires one, including roots that manage only ZeroKMS resources or read data sources. Control-only credentials that previously configured the provider are now rejected. Create this credential outside the Terraform configuration that uses it: the provider cannot safely manage its own authentication credential. See the [provider reference](docs/index.md) for the credential arguments.

```hcl
provider "cipherstash" {
  auth = {
    workspace_crn = var.workspace_crn
    # Supply an Admin credential through CS_CLIENT_ACCESS_KEY.
  }
}
```

Supply the key securely through `CS_CLIENT_ACCESS_KEY` or the sensitive `client_access_key` argument. For both `workspace_crn` and `client_access_key`, an omitted or null argument uses its environment variable; `auth = {}` takes both from the environment. Explicit known values override the environment. Empty, unknown or malformed selected values fail without falling back to another source. Credentials without Admin, including Control-only and Member-only credentials, are rejected even though the environment variable is named `CS_CLIENT_ACCESS_KEY`.


`CS_CLIENT_ID` identifies an application encryption client, not an authentication principal. Neither `manage.Config` nor the provider requires or reads it, and neither automatically grants that client access. Use `cipherstash_zerokms_keyset_grant` to manage explicit pairs. Application client keys remain separate from provider authentication.

`CS_CTS_HOST` replaces the workspace region's CipherStash Token Service (CTS), as it does in CipherStash's SDKs, for example to use a staging CTS or a local fake. The provider then sends the access key, token exchanges, signing-key requests and actor and access-key management to that URL, and requires tokens to name it as their issuer. It must be an HTTPS URL, or HTTP to a loopback host such as `http://localhost:3001`, without credentials, query or fragment; anything else fails with "Invalid CTS host" before any request. An empty value is ignored. The ZeroKMS endpoint still comes from the verified token. Only set `CS_CTS_HOST` in environments you control: whoever chooses it receives the Admin key.

Native authentication verifies each exchanged token's RS256 signature against the CipherStash Token Service (CTS) signing keys, issuer, audience, expiry, workspace and Admin role. It also validates the advertised ZeroKMS endpoint before use. Each provider instance owns its token cache and authentication lifetime; reconfiguration and shutdown cancel token refresh. CTS and ZeroKMS still authorize each service request. Successful provider configuration does not prove that a later administration request will be permitted. Use the narrower Member or Control roles for application workloads where appropriate; the provider's Admin requirement does not mean your application needs Admin.

### Connect to PostgreSQL

`database` takes `host`, `port`, `username`, `password`, `sslmode` and `sslrootcert`. Unset arguments fall back to libpq's `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGSSLMODE` and `PGSSLROOTCERT`, and to the password file. There is no database name: each `cipherstash_eql_v4` resource names the database it installs into. Use `sslmode = "verify-full"` outside local development.

```hcl
provider "cipherstash" {
  database = {
    host     = aws_rds_cluster.app.endpoint
    username = "postgres"
    password = ephemeral.aws_secretsmanager_secret_version.master.secret_string
    sslmode  = "verify-full"
  }
}
```

The provider opens one connection per operation and only when a resource needs it, so these values may come from resources created in the same apply. Operations that run before those values are known fail with a fixed message. Database diagnostics describe the failure by its SQLSTATE class and never include PostgreSQL's message, which can quote submitted values; PostgreSQL notices go to the provider's debug log.

### Migrate from top-level credentials

This is a breaking configuration change with no compatibility aliases. Move the credential arguments into `auth`:

| Before | After |
| --- | --- |
| `workspace_crn = …` | `auth = { workspace_crn = … }` |
| `client_access_key = …` | `auth = { client_access_key = … }` |
| An empty provider block configured from `CS_*` variables | `auth = {}` |

The old top-level arguments are rejected with "Unsupported argument". An empty provider block no longer reads `CS_WORKSPACE_CRN` or `CS_CLIENT_ACCESS_KEY`: CipherStash resources then fail with "Provider auth settings required". Resource arguments and state are unchanged.

Earlier names are also rejected or ignored: the `crn`, `access_key` and `control_access_key` arguments, and the `CIPHERSTASH_ACCESS_KEY` and `CS_CONTROL_ACCESS_KEY` environment variables.

### Protect state and credentials

Terraform marks returned access keys and client key values as sensitive, but **stores resource secrets in state and saved plans**. Sensitive marking hides values in normal display; it does not encrypt them or prevent JSON/raw outputs from revealing them. Sensitive provider inputs can also appear in saved plans. Reading the provider's access key from the environment is not the same as storing a resource's returned key in state.

Use an encrypted state backend with restricted access. Protect backups and saved plans, and never commit credentials, state, or plan files. The provider does not display upstream error bodies, which can contain submitted data. The provider clears exported creation-secret buffers, but Terraform still holds string copies.

## Choose what Terraform manages

Names identify the owning service: `cts` means CipherStash Token Service, which manages actors and their authentication access keys; `zerokms` identifies encryption clients, keysets and grants; `eql` identifies Encrypt Query Language, the PostgreSQL types and functions for encrypted values. An actor's `access_key` and a ZeroKMS client's `client_key` are different credentials.

| Resource or data source | What it manages | Change behavior |
| --- | --- | --- |
| [`cipherstash_cts_actor`](docs/resources/cts_actor.md) | A machine identity and its access key | Any argument change replaces the actor and creates a new key. |
| [`cipherstash_zerokms_client`](docs/resources/zerokms_client.md) | A ZeroKMS client and its client key | Name/description changes replace the client; grants are not transferred. |
| [`cipherstash_zerokms_keyset`](docs/resources/zerokms_keyset.md) | A keyset's name, description, and enabled status | Updates the existing keyset. Destroy disables it; it does not delete key material. |
| [`cipherstash_zerokms_keyset_grant`](docs/resources/zerokms_keyset_grant.md) | One client/keyset grant | Changing either ID replaces the grant. Destroy revokes only that pair. |
| [`cipherstash_zerokms_client` data source](docs/data-sources/zerokms_client.md) | Read-only client metadata | Does not import, change, or delete the client or its grants. |
| [`cipherstash_eql_v4`](docs/resources/eql_v4.md) | EQL v4 installed in one PostgreSQL database | Changing `database` replaces it; changing `version` is rejected. Destroy never uninstalls EQL. |

These names replace the earlier development types `cipherstash_actor`, `cipherstash_client`, `cipherstash_keyset` and `cipherstash_keyset_grant`. The old names are not registered, and there is no automatic cross-type state migration. If existing state uses the old types, retain the previous provider binary and protected state backups until you have planned a migration. Changing HCL type names alone does not migrate state. Import cannot recover creation-only credentials.

Give each managed object one owner. For example, Terraform can manage a shared application keyset while a provisioning worker manages tenant keysets. Do not let the worker and Terraform manage the same keyset or grant pair. This provider has no workspace or human-membership resources.

### Manage client access

Declare an ordinary `cipherstash_zerokms_client` for each application client. Create does not choose a keyset, so CipherStash creates the workspace's default keyset if it does not exist yet, or reuses it, and grants the new client access to it. CipherStash owns that default keyset and those grants: you do not need to import or manage either, and there is no input for the default keyset's name or description. The client resource manages identity, not grants. Refresh preserves the client key even if the client has no grants.

Use `cipherstash_zerokms_keyset_grant` for access to keysets you manage, such as a shared application keyset; provisioning automation can own tenant keysets and their grants the same way. It manages one `(client_id, keyset_id)` pair, not the client's entire grant list. Import an existing pair rather than creating it again: creation refuses to silently adopt a grant. Grant import checks that the pair exists without changing service state. Importing a client's default-keyset grant still works, but it is not needed. To stop managing such a grant, use a `removed` block that sets `lifecycle { destroy = false }`: destroying it asks CipherStash to revoke the client's creation grant, which it refuses, as the next paragraph describes.

CipherStash refuses to revoke a client's creation grant: the grant to the keyset the client was created with, which is the workspace's default keyset unless another was chosen. The revoke request returns HTTP 400, so destroying a grant resource for that pair fails with "Cannot revoke keyset grant", reports that CipherStash rejected the request as invalid (HTTP 400), and keeps the pair in state. To remove that access, delete the client. Every other grant can be revoked.

Client refresh and import never add, restore or revoke grants, and never enable, rename or disable the default keyset. Deleting a client deletes only the client; the default keyset stays enabled for every other client. Use the `cipherstash_zerokms_client` data source's `keyset_ids` to read current grant inventory.

Replacing a client creates a different identity. Grants associated with the old client are not transferred to it. Plan credential and grant changes separately; consider `lifecycle { prevent_destroy = true }` for an established client. This provider does not implement an application cutover or prove that deleting a client physically removes every grant record on the service.

### Read an existing client

Use the client data source when you need metadata without taking ownership:

```hcl
data "cipherstash_zerokms_client" "api" {
  id = "11111111-1111-4111-8111-111111111111" # Replace with your existing client ID.
}
```

The lookup returns the client's `name`, `description`, and all granted `keyset_ids`, including disabled keysets. No grants produces an empty set; a missing client or failed lookup produces an error. The lookup does not select a keyset or retrieve the client key value. Keep existing secrets in your secret store. Removing the data source does not delete the client.

### Install EQL v4

`cipherstash_eql_v4` installs EQL v4 into the database named by `database`, on the server from the provider's `database` settings. `version` must be a version compiled into the provider, such as `go-0.1.0-rc.3`; the provider contains each version's `eql-v4-install.sql` release asset byte for byte and checks it against its SHA-256. Until cipherstash/stack publishes a stable Go release, the provider contains only the latest release candidate and the one before it.

```hcl
resource "postgresql_extension" "pgcrypto" {
  name   = "pgcrypto"
  schema = "public"
}

resource "cipherstash_eql_v4" "app" {
  database   = "app"
  version    = "go-0.1.0-rc.3"
  depends_on = [postgresql_extension.pgcrypto]
}
```

Create runs the installer in one transaction with `search_path = public`, under the advisory lock the `stash` CLI uses, and with its own lock and statement timeouts. It changes nothing and fails if:

- the database already has an `eql_v4` or `eql_v4_internal` schema, including a partial one: import an existing installation with `terraform import cipherstash_eql_v4.app app` or an `import` block instead;
- another installation holds the lock;
- `pgcrypto` is in a schema other than `public` or `extensions`;
- the role lacks `CREATE` on the database or on `public`;
- after the installer runs, `eql_v4.version()` does not match, or the ORE operator class is missing while `require_ore` is `true` (the default). Creating that class needs a superuser, or `rds_superuser` on Amazon RDS and Aurora. Set `require_ore = false` to accept an installation whose 20 ORE-backed domains are disabled.

Install `pgcrypto` first, as above. Without it, the installer creates `pgcrypto` in a new `extensions` schema, and every role that compares ORE-encrypted values also needs `USAGE` on that schema.

EQL issues no grants. Roles that query encrypted columns need `USAGE` on both EQL schemas. Grant it with the community PostgreSQL provider and reference the resource's `schema` and `internal_schema` attributes, so one apply installs EQL before granting on it:

```hcl
resource "postgresql_grant" "app_eql" {
  for_each    = toset([cipherstash_eql_v4.app.schema, cipherstash_eql_v4.app.internal_schema])
  database    = "app"
  role        = "app"
  schema      = each.key
  object_type = "schema"
  privileges  = ["USAGE"]
}
```

Refresh reads the installed version, owner, ORE availability and `pgcrypto` schema, and removes the resource only when a successful read shows EQL absent. The provider cannot upgrade EQL yet: the installer drops and re-creates both EQL schemas, removing every grant and every index built on EQL functions, so changing `version` is rejected at plan time. Upgrade by hand instead, as below.

#### Upgrade EQL by hand

Plan a maintenance window: from the reinstall until the grants are restored, roles other than the installing role get `permission denied for schema eql_v4`, and queries cannot use the dropped indexes until they are re-created.

1. Record the indexes that the reinstall will drop:

   ```sql
   SELECT DISTINCT pg_get_indexdef(d.objid) || ';'
   FROM pg_depend d
   JOIN pg_proc p ON p.oid = d.refobjid
   WHERE d.classid = 'pg_class'::regclass
     AND d.refclassid = 'pg_proc'::regclass
     AND p.pronamespace IN ('eql_v4'::regnamespace, 'eql_v4_internal'::regnamespace);
   ```

2. Stop managing the installation without changing the database: `terraform state rm cipherstash_eql_v4.app`. Don't apply until step 4, because Create refuses an existing installation.
3. Run the new version's `eql-v4-install.sql`, from the cipherstash/stack Go release, as the role that installed EQL, in one transaction with `search_path` set to `public`:

   ```sh
   PGOPTIONS='-c search_path=public' psql --single-transaction -v ON_ERROR_STOP=1 -f eql-v4-install.sql
   ```

4. Set `version` to the new version, import the installation with `terraform import cipherstash_eql_v4.app app` or an `import` block, and apply. Grant resources such as `postgresql_grant` find the `USAGE` grants missing and grant them again in the same apply.
5. Run the statements from step 1, then `ANALYZE` the tables they index.

The installer creates the column types in `public` only when they don't exist, so an upgraded database keeps the column types of the version first installed. Check the release notes for changes to them before upgrading.

Destroy does not uninstall EQL: uninstalling would break every column typed with an EQL domain, and the domains in `public` would remain. Destroy fails while EQL is installed and succeeds once it is gone. To stop managing an installation, use a `removed` block with `lifecycle { destroy = false }` or `terraform state rm`. Because Terraform destroys dependents first, a `terraform destroy` of a root like the one above revokes the grants before failing on EQL.

## Understand lifecycle and recovery

### Replace an actor or client

Changing any actor argument, or a client's name or description, requires replacement and creates a new credential. Client metadata updates are not supported by the published ZeroKMS API. An actor's `token_expiry` sets the lifetime of tokens issued from its access key, not the lifetime of the key itself. If omitted, CTS uses 900 seconds. The API does not return this setting, so Terraform cannot detect changes made outside Terraform.

Actor and client deletion accept a successful service response or an already-absent response; the provider does not then check inventory. Separate live checks observed removal from inventory, but that is not proof of immediate credential revocation. In a disposable development workspace, a deleted actor's key still succeeded in a new token exchange after the actor and its key disappeared from listings. The revocation delay is unknown. Before a security-sensitive credential change, verify when the old credential and already-issued tokens stop working.

### Import existing objects

Import brings an existing object under Terraform management; it does not recover a secret returned only at creation.

| Resource | Import ID | What import cannot do |
| --- | --- | --- |
| Actor | Actor ID, such as `app-JBSWY3DPEHPK3PXP` | Recover `access_key` or `token_expiry`; both are null after import. Setting a token lifetime afterward can require replacement. |
| Client | Client UUID, with zero, one or many grants | Recover `client_key` or change grants. |
| Keyset | Keyset UUID | Delete key material or select the workspace default. Import refuses the workspace default keyset, which CipherStash owns. Import includes disabled keysets; set `enabled = false` to keep one disabled. |
| Grant | `client UUID/keyset UUID` | Create the pair or change other grants. |

The example IDs are placeholders. To keep an imported actor or client, use its previously saved credential from your secret store. To obtain a new credential, replace the resource and plan the change for its consumers.

To have Terraform own one of a client's grants, import that pair separately as a `cipherstash_zerokms_keyset_grant`.

### Disable or stop managing a keyset

`cipherstash_zerokms_keyset` creates a keyset without a client or grant and never exports its key material. Name, description, and enabled-status changes update the same keyset without rotating key material. The metadata and enabled-status requests are separate operations, not a transaction. Terraform records successful steps and the values returned by a follow-up read, including after a failed write.

CipherStash rejects metadata updates while a keyset is disabled. When a plan enables a disabled keyset and changes metadata, the provider enables it first. When a plan changes metadata and disables an enabled keyset, it updates metadata first. An already-disabled keyset must have `enabled = true` planned to change its metadata; the provider never temporarily enables a keyset configured to remain disabled. If enabling succeeds but the metadata update fails, the keyset remains enabled and Terraform retains that partial success.

Destroy disables the keyset, confirms that it is disabled or absent, and removes it from state. The keyset and key material remain in CipherStash. An already-disabled keyset needs no write. A failed disable, failed follow-up read, or still-enabled result returns an error and retains state. Disabling can interrupt every client using the keyset, including clients with worker-managed grants; the grants themselves remain.

Import does not enable a disabled keyset, but configuration defaults `enabled` to `true`. Set `enabled = false` to keep it disabled. A new keyset is always created enabled; `enabled = false` is applied afterward, with the returned ID saved first. If that request fails, inspect state and the next plan before retrying. To manage a keyset again after destroy, import its retained ID. The provider does not automatically adopt an existing keyset by name.

The workspace default keyset is not a keyset this resource manages. Import refuses it. If state already holds it, for example from an earlier import, refresh fails with "Cannot manage the workspace default keyset", so a refreshed plan cannot rename, re-describe, enable, disable or destroy it. Update and destroy also check live inventory before writing and refuse the default, so `terraform apply -refresh=false` cannot change it either. Remove it from management with a `removed` block that sets `lifecycle { destroy = false }`; that works even though refresh fails.

Use `lifecycle { prevent_destroy = true }` to reject a destroy plan while the resource block remains configured. It does not prevent an in-place `enabled = false` update, and it stops protecting the resource if you remove the entire block. To stop managing a keyset without disabling it, use Terraform's `removed` block with `lifecycle { destroy = false }` rather than a normal destroy.

### Recover from a failed apply

A failed apply does not mean nothing was created. The provider saves returned IDs and secrets before additional metadata reads. When a later step fails, Terraform can keep the resource in state and mark it tainted, meaning a later plan may replace it. Inspect service inventory, Terraform state, and the next plan before retrying.

If a create request succeeds but its response is lost, the provider may never receive the new object's ID. Writes are not automatically retried. Inspect inventory and import an existing object before retrying a conflicting create.

Refresh removes absent resources from state only after a successful lookup. Authentication or listing errors are not evidence of absence. Client and keyset inventories with invalid UUIDs or repeated identity fields, or client entries with missing/null descriptions, fail refresh without changing saved state. An empty description and an empty grant array remain valid. An actor with missing or ambiguous access-key metadata stays in state with an error. Existing creation secrets are retained during refresh.

A grant's ID is known before the request because it is the client/keyset pair. After attempting creation, the provider saves that pair before reading it back. A failed write remains an error, and the pair stays in state unless a follow-up read confirms it is absent. A failed revoke counts as complete only if a follow-up read confirms absence; Terraform reports a warning about the failed request. No write is retried automatically.

### Live verification limits

**Live API probes are not full Terraform keyset/grant lifecycle verification.** On 2026-10-30, isolated Development probes found that revoking a client's creation grant returned HTTP 500, both while another grant remained and when it was the client's only grant. CipherStash then changed the service. On 2026-11-02, the same probes, run with Admin and Control keys through `pkg/stack/manage`, observed:

| Request | Response |
| --- | --- |
| Grant a keyset the client already has | HTTP 409, `Client already has access to this keyset` |
| Revoke a grant added after creation | HTTP 200; the grant leaves inventory |
| Revoke the creation grant: on the default keyset with and without another grant, and as the only grant on a non-default keyset | HTTP 400, `Cannot revoke a client's default keyset (the keyset it was created with); delete the client instead` |
| Revoke a grant the client no longer has | HTTP 404 |

Error bodies are plain text. Inventory confirmed that refused requests left grants unchanged. The provider does not show response bodies in diagnostics, so Terraform reports only the category: HTTP 400 as an invalid request, 409 as a conflict and 404 as not found.

The probes deleted their test clients and preserved existing resources. Test keyset `9fc1fcf6-da8a-4b8f-abdc-aae2405d6651` and the keysets named `adhoc-grant-probe-*` remain disabled because keysets cannot be deleted. Exercise the actual Terraform keyset/grant lifecycle before production use; the API probes do not replace that check.

Before the BNDRY migration, on 2026-10-30, the native-backed actor/client acceptance test passed creation, refresh, UUID and legacy-pair imports, replacement and deletion in workspace `2JTSJCX24VP2WCBC`. Actor, access-key and client IDs matched the pre-test baseline afterward. A subsequent direct `internal/stack` client test verified Admin authentication, client creation, metadata and grant inventory, filtering, one-time key export and deletion. Go and the published Rust protocol decoder accepted the live inventories, including scalar and array grant representations. Complete client/keyset inventories matched that run's baseline afterward: two clients and nine keysets, eight disabled. No new lasting resource was created by that run.

The BNDRY-backed provider repeated the actor/client Terraform acceptance test on 2026-10-30 in Development workspace `2JTSJCX24VP2WCBC`, using a temporary module replacement for the local inventory-hardening fix. Creation, refresh, UUID and legacy-pair imports, replacement and deletion passed; actor, access-key and client IDs matched the baseline afterward. This run did not repeat the keyset/grant lifecycle or validate a published dependency containing that fix.

Live zero-grant inventory representation remains unverified, and revocation cannot produce a zero-grant client because the creation grant cannot be revoked. Offline Terraform CLI tests cover zero-grant import and refresh; accepting an empty array in a fixture is not live evidence. None of these checks establishes immediate credential invalidation after deletion; see the actor-key observation above.

### Migrate from earlier client and keyset attributes

These are breaking changes with no compatibility aliases. Existing state needs no manual edit unless it holds the workspace default keyset.

| Removed | What to do |
| --- | --- |
| The client's computed `keyset_id` | Read current grants from the `cipherstash_zerokms_client` data source's `keyset_ids`. References to `cipherstash_zerokms_client.<name>.keyset_id` fail with "Unsupported attribute". Existing state loads without error, and Terraform drops the stored value the next time it writes state. |
| Client import IDs of the form `client UUID/keyset UUID` | Import the client by its UUID. Import the pair as a `cipherstash_zerokms_keyset_grant` if Terraform should own that grant. |
| `client_key_client_id`, and setting `client_key` in configuration | Remove both arguments; `client_key` is now read-only. A key already in state, including one recorded this way, stays there. Keep keys for imported clients in your secret store. |
| The keyset's computed `is_default` | None. If a `cipherstash_zerokms_keyset` resource holds the workspace default keyset, refresh now fails; replace its resource block with a `removed` block that sets `lifecycle { destroy = false }`. |

### Preserve existing configuration

The repository's earlier example configurations have been removed; `examples/eql-quickstart` is the configuration from the EQL guide and is not a replacement for them. If you used the earlier examples, preserve your configuration and state until you have planned a migration. Do not apply an emptied root against retained state: Terraform would plan to destroy the resources it no longer sees in configuration.

## Develop and verify locally

Install [mise](https://mise.jdx.dev/). `mise.toml` pins Go 1.27.3 and Terraform 1.14.6 and sets `GOWORK=off`, so builds and tests use only this repository's module dependencies. All dependencies are public, and `go.mod` has no module replacements. A standalone checkout needs no access to BNDRY or a sibling SDK checkout.

```sh
mise trust
mise install
mise run check
mise run install-local
export TF_CLI_CONFIG_FILE="$PWD/.local/terraform.rc"
```

These commands check and install the provider locally without creating CipherStash resources. Use your own Terraform root with the local provider address and version above. To plan against a workspace, supply its Admin access key securely through `CS_CLIENT_ACCESS_KEY`; do not put the key in shell history or committed variable files. Review the plan and coordinate shared-workspace access before any apply.

A lockfile generated from the local mirror describes your local build, not a published provider. After rebuilding changed source, refresh that root's provider checksum with `terraform providers lock -fs-mirror=<provider checkout>/.local/mirror terraform.local/cipherstash/cipherstash` before initializing again. Do not use this development-version process for a production lockfile.

### Run local checks

| Command | What it does |
| --- | --- |
| `mise run check` | Runs race-enabled tests, Go vet, and Go and `examples/` Terraform formatting checks without changing tracked files or contacting live services. |
| `mise run test` | Runs offline Terraform CLI and fixture tests with `TF_ACC` cleared, even if acceptance is enabled in your shell. The race detector needs a C toolchain. |
| `mise run test:postgres` | Runs the EQL installation tests against the PostgreSQL superuser connection in `CS_TEST_POSTGRES_URL`. Each test creates and drops its own database and roles. It limits the upgrade model to 10 random traces of about 10 actions, after its fixed traces. |
| `mise run examples:validate` | Installs the provider into the local mirror and runs `terraform validate` on each directory in `examples/`. It downloads the other providers the examples use. |
| `mise run build` | Builds the local provider binary. |
| `mise run codegen` | Runs `go generate ./...`: generates reference pages from Go schema descriptions using tfplugindocs 0.25.0, and the API clients under `pkg/stack/internal` using oapi-codegen. Edit those descriptions, not `docs/` directly. CI fails if the committed files differ from the output. |
| `mise run --env test lint` | Runs optional golangci-lint 2.14.0 from `mise.test.toml`. It is separate from `check`. |
| `mise run --env docs site` | Builds the documentation site from `docs/` with Zensical, pinned in `mise.docs.toml`, into `site/`. `mise run --env docs site:serve` previews it. The Docs workflow publishes it to the `gh-pages` branch when `docs/` changes on `main`. |

Documentation generation, the PostgreSQL tests and live acceptance are not part of `check`. To run the PostgreSQL tests locally, start a disposable server, for example `docker run --detach --name eql-test --env POSTGRES_PASSWORD=postgres --publish 55432:5432 postgres:17`, and set `CS_TEST_POSTGRES_URL='postgres://postgres:postgres@localhost:55432/postgres?sslmode=disable'`. This repository does not configure Rust or guest builds, and does not force `CGO_ENABLED=0`.

### Understand test coverage

The offline suite has four layers, and a fifth runs against PostgreSQL:

| Layer | What it establishes |
| --- | --- |
| Terraform CLI (`cli_test.go`) | Real Terraform 1.14.6 plans, applies, persisted imports, refresh, replacement and destroy through the protocol server. Checks dependent resources and lookups, sensitive secrets, grant ownership, external drift and validation. Failed-create and create-before-destroy cases inspect the next plan's saved identities and secrets, including deposed objects, then recover and check for orphans. |
| Direct native-backed tests (`failures_test.go`, `crud_test.go`, `provider_test.go`) | State retention on failed inventory reads, pagination and metadata ambiguity, partial keyset writes, uncertain grant/revoke outcomes, confirmed destroy, credential precedence, independent authentication lifetimes and cancellation. Native authentication verifies signed fixture tokens against local signing-key and HTTP fixtures; upstream error bodies must not enter diagnostics. |
| Direct resource tests (`resources_test.go`) | Focused reconciliation tests with injected `manage` client results, including import restrictions, missing objects and partial failures. |
| Public SDK (`pkg/stack/auth`, `pkg/stack/manage`) | Signed-token validation and refresh, service request contracts, malformed-inventory rejection, zero-grant clients, one-time secret export, cancellation, and no write retries or redirects. These tests use local service fixtures, not live credentials. |
| PostgreSQL (`internal/eql`, `TestCLIPostgres*` in `cli_test.go`) | Runs only with `CS_TEST_POSTGRES_URL`. Installs EQL as a superuser and as a role without it, checks that every refusal leaves the database unchanged, and runs Terraform against the database: apply, import, refresh after an out-of-band uninstall, destroy refusal, and import of an installation made outside Terraform. A rapid state machine (`TestCLIPostgresEQLUpgradeModel`) runs Terraform through every upgrade path between the compiled-in versions: changing `version` is rejected with nothing changed, and an upgrade made by hand is adopted by removing the resource from state, reinstalling and importing. It also checks that no Terraform action changes a table of EQL-typed columns or its functional indexes, that a reinstall drops those indexes, and that re-creating them binds the expected operator classes. The Tests workflow runs it against PostgreSQL 16 and 17. |

CLI tests use `resource.UnitTest`, so they run without live-acceptance opt-in. They require the pinned Terraform on `PATH` and fail rather than download another version. Run them through mise, which supplies the actual executable rather than a tool shim. Each case uses a temporary CLI configuration and fake credentials. The in-process provider's transport only permits local fixture routing. Tests run serially because they replace the process-default transport and environment. This setup tests separate provider session ownership directly, not Terraform provider aliases or binary installation.

The shared service fixture models inventory and HTTP faults, not Terraform plans or state. Unexpected endpoints, malformed requests, handler panics and unused fault injections fail tests independently of provider diagnostics. Default tests clear `TF_ACC`: plugin-testing treats any nonempty value, including `0`, as opt-in.

Run just the CLI layer with `mise exec -- go test ./internal/provider -run '^TestCLI' -count=1 -v`. These tests need only this checkout and the pinned tools. They establish neither live permissions nor live keyset/grant lifecycle behavior.

Separate live checks verified that client creation without a specified keyset grants the default keyset, and that deleted clients disappear from inventory. Unique actor names returning 409 remain a fixture assumption, not recorded live proof. Removing a client from the fixture makes its grants unobservable; this does not prove deletion of grant records on the service. Real Admin and Control re-grant probes returned HTTP 409 with the grant unchanged.

### Run approved live acceptance tests

Live actor/client tests use `terraform-plugin-testing`. Coordinate access to the shared workspace and explicitly set `TF_ACC=1`, `TF_ACC_WORKSPACE_ID`, a matching `TF_ACC_CRN`, and `CS_CLIENT_ACCESS_KEY` containing an Admin key for provider authentication. Then run `mise run test:acc`.

There is no default acceptance workspace. The task refuses to run without opt-in, and the test rejects a missing workspace ID, mismatched CRN, or missing credential before opening authentication. It creates uniquely named `tf-acc-*` actors and clients, checks refresh/import/replacement, destroys them, and compares actor, access-key, and client IDs against the initial inventory. It does not separately mutate keysets or grants.

The Acceptance workflow runs this test on pushes to `main` and on manual dispatch, one run at a time, using the `CS_WORKSPACE_CRN` and `CS_CLIENT_ACCESS_KEY` repository secrets. Pull requests run only the offline suite.

## Distribution and licensing

This repository is licensed under the [MIT License](LICENSE.md), the same licence as [cipherstash/stack](https://github.com/cipherstash/stack). The licence covers the provider and the public `pkg/stack/auth` and `pkg/stack/manage` packages. Go module dependencies keep their own licences.

Release automation, signing and publication are outside this development build workflow. This repository publishes no provider binaries or Terraform Registry artifacts.
