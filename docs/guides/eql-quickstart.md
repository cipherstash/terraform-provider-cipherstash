---
page_title: "Prepare CipherStash and PostgreSQL for encrypted data with Terraform"
subcategory: ""
description: |-
  Create an application's CipherStash credentials, install EQL v4 into PostgreSQL and grant the application's database role access to it, from one Terraform configuration.
---

# Prepare CipherStash and PostgreSQL for encrypted data with Terraform

An application that stores encrypted data with CipherStash needs two things before it can run. It needs credentials for CipherStash's key service, and it needs a PostgreSQL database that understands encrypted values. Setting these up by hand means clicking through the CipherStash Dashboard, copying four secrets into your deployment, and running a 60,000-line SQL script against the database. Nobody can repeat that process exactly, or review it.

The CipherStash Terraform provider does all of it from one configuration file. In this tutorial, you'll use it to set up an imaginary invoices service. You'll give it its own encryption keys and credentials, install CipherStash's encrypted query support into a local PostgreSQL database, and grant the service's database role access to it.

## What you'll build

By the end, two commands confirm the setup. The first prints the four environment variables the invoices service needs (values shortened here):

```text
$ terraform output -json app_environment
{"CS_CLIENT_ACCESS_KEY":"CSAKJBSWY3DPEHPK3PXP.6Zq…","CS_CLIENT_ID":"4f8e2a6c-1b3d-4e5f-9a7b-8c6d5e4f3a2b","CS_CLIENT_KEY":"o2FrZXlzZXRf…","CS_WORKSPACE_CRN":"crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"}
```

The second connects to the database as the service's own role and asks which version of CipherStash's encrypted query support is installed:

```text
$ docker exec --env PGPASSWORD="${INVOICES_APP_PASSWORD?}" invoices-postgres \
    psql --host=127.0.0.1 --username=invoices_app --dbname=invoices \
    --tuples-only --no-align --command='SELECT eql_v4.version();'
go-0.1.0-rc.3
```

## A few terms

- **CipherStash workspace**: your account's isolated space in CipherStash. Its **workspace CRN** is an identifier such as `crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY`, which names both the workspace and its region.
- **Access key**: a credential, beginning with `CSAK`, that lets a program talk to CipherStash. Each key has a role. `admin` can manage the workspace, and `member` can only encrypt and decrypt.
- **Keyset**: a set of encryption keys. Data encrypted under one keyset can't be decrypted with another, so you'd typically use one keyset per application or tenant.
- **Client** and **client key**: an application's half of CipherStash's split-key design. A client can only use the keysets it has been granted.
- **EQL**, short for Encrypt Query Language: a set of PostgreSQL types and functions that let the database store, compare and index encrypted values. Version 4 lives in the schemas `eql_v4` and `eql_v4_internal`.

## Before you start

You need:

- A CipherStash workspace you can experiment in. The keyset you create in this tutorial can be disabled but not deleted, so don't use a production workspace.
- An access key for that workspace with the `admin` role. Create one on the **Access Keys** page of the [CipherStash Dashboard](https://dashboard.cipherstash.com/workspaces/_/access-keys), and copy the workspace CRN shown in the Dashboard. The provider uses the key only to create the other resources. Your application never sees it.
- Terraform 1.14. This tutorial uses Terraform 1.14.6.
- Docker, to run PostgreSQL 16.11 locally.
- Git and [mise](https://mise.jdx.dev), to build the provider. The provider isn't in the Terraform Registry yet.

## Install the CipherStash provider

Build the provider and install it into a local mirror that Terraform can read:

```shell
git clone https://github.com/cipherstash/terraform-provider-cipherstash.git && \
  cd terraform-provider-cipherstash && \
  mise trust && \
  mise install && \
  mise run install-local && \
  export TF_CLI_CONFIG_FILE="$PWD/.local/terraform.rc" && \
  cd ..
```

`TF_CLI_CONFIG_FILE` tells Terraform to load the CipherStash provider from that mirror. Run the remaining steps in the same terminal so the variable stays set.

## Set your credentials

Set the values that are specific to you. Replace the workspace CRN with your own, and pick a password for the local database. The password can be anything, because the database only runs on your machine.

```shell
# Replace with your workspace CRN from the CipherStash Dashboard.
export TF_VAR_workspace_crn='crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY'

# Password for the local PostgreSQL superuser. Any value works.
export PGPASSWORD='mellow-lantern-58'
```

Then enter your Admin access key without it appearing on screen or in your shell history:

```shell
read -r -s -p 'Admin access key: ' CS_CLIENT_ACCESS_KEY && \
  export CS_CLIENT_ACCESS_KEY && \
  echo
```

The provider reads `CS_CLIENT_ACCESS_KEY` from the environment, so the key never appears in your configuration files.

## Create the invoices service's CipherStash credentials

Create a directory for the configuration:

```shell
mkdir invoices-infra && cd invoices-infra
```

Create `invoices-infra/main.tf` with the following contents:

```terraform
# invoices-infra/main.tf
terraform {
  required_version = "~> 1.14.0"

  required_providers {
    cipherstash = {
      source  = "terraform.local/cipherstash/cipherstash"
      version = "0.0.1"
    }
  }
}

variable "workspace_crn" {
  type = string
}

provider "cipherstash" {
  # Connect to CipherStash. The Admin access key comes from CS_CLIENT_ACCESS_KEY.
  auth = {
    workspace_crn = var.workspace_crn
  }
}

# The keys that will encrypt invoice data.
resource "cipherstash_zerokms_keyset" "invoices" {
  name        = "invoices"
  description = "Customer invoices"
}

# The invoices service's half of the split key.
resource "cipherstash_zerokms_client" "invoices_api" {
  name        = "invoices-api"
  description = "Invoices API service"
}

# Allow the invoices service to use the invoices keyset.
resource "cipherstash_zerokms_keyset_grant" "invoices_api" {
  client_id = cipherstash_zerokms_client.invoices_api.id
  keyset_id = cipherstash_zerokms_keyset.invoices.id
}

# The invoices service's identity and its own access key. The member role
# can encrypt and decrypt, but can't change the workspace.
resource "cipherstash_cts_actor" "invoices_api" {
  name = "invoices-api"
  role = "member"
}

# The four environment variables the invoices service needs.
output "app_environment" {
  sensitive = true
  value = {
    CS_WORKSPACE_CRN     = var.workspace_crn
    CS_CLIENT_ID         = cipherstash_zerokms_client.invoices_api.id
    CS_CLIENT_KEY        = cipherstash_zerokms_client.invoices_api.client_key
    CS_CLIENT_ACCESS_KEY = cipherstash_cts_actor.invoices_api.access_key
  }
}
```

Initialize Terraform, review the plan, and apply it:

```shell
terraform init && \
  terraform plan -out=invoices.tfplan && \
  terraform apply invoices.tfplan
```

The plan should end with `Plan: 4 to add, 0 to change, 0 to destroy.` When the apply finishes, print the service's environment:

```shell
terraform output -json app_environment
```

You should see the four `CS_*` variables from [What you'll build](#what-youll-build). In a real deployment, you'd store these in your secret manager. Terraform also keeps them in its state file, so protect that file too.

## Start a local PostgreSQL database

Start PostgreSQL 16.11 with a database named `invoices`, and wait until it accepts connections:

```shell
docker run \
  --detach \
  --name invoices-postgres \
  --env POSTGRES_PASSWORD="${PGPASSWORD?}" \
  --env POSTGRES_DB=invoices \
  --publish 5432:5432 \
  postgres:16.11 && \
  until docker exec invoices-postgres \
    pg_isready --host=127.0.0.1 --username=postgres --dbname=invoices --quiet; do
    sleep 1
  done
```

EQL compares some encrypted values using the `pgcrypto` extension, so add it to the database's `public` schema:

```shell
docker exec invoices-postgres \
  psql --username=postgres --dbname=invoices --command='CREATE EXTENSION pgcrypto;'
```

If `pgcrypto` were missing, the EQL installer would create it in a separate `extensions` schema, and every database role using encrypted ordering would then need an extra grant on that schema.

## Install EQL v4 into the database

Replace the contents of `invoices-infra/main.tf` with the following. Two things change: the provider block gains a `database` connection, and a new `cipherstash_eql_v4` resource installs EQL.

```terraform
# invoices-infra/main.tf
terraform {
  required_version = "~> 1.14.0"

  required_providers {
    cipherstash = {
      source  = "terraform.local/cipherstash/cipherstash"
      version = "0.0.1"
    }
  }
}

variable "workspace_crn" {
  type = string
}

provider "cipherstash" {
  # Connect to CipherStash. The Admin access key comes from CS_CLIENT_ACCESS_KEY.
  auth = {
    workspace_crn = var.workspace_crn
  }

  # Connect to PostgreSQL. The password comes from PGPASSWORD.
  database = {
    host     = "localhost"
    port     = 5432
    username = "postgres"
    sslmode  = "disable" # The local container has no TLS. Use "verify-full" in production.
  }
}

resource "cipherstash_zerokms_keyset" "invoices" {
  name        = "invoices"
  description = "Customer invoices"
}

resource "cipherstash_zerokms_client" "invoices_api" {
  name        = "invoices-api"
  description = "Invoices API service"
}

resource "cipherstash_zerokms_keyset_grant" "invoices_api" {
  client_id = cipherstash_zerokms_client.invoices_api.id
  keyset_id = cipherstash_zerokms_keyset.invoices.id
}

resource "cipherstash_cts_actor" "invoices_api" {
  name = "invoices-api"
  role = "member"
}

# Install EQL v4 into the invoices database. The provider contains the
# installer for each supported version; this is the version that matches
# release v0.1.0-rc.3 of CipherStash's Go library.
resource "cipherstash_eql_v4" "invoices" {
  database = "invoices"
  version  = "go-0.1.0-rc.3"
}

output "app_environment" {
  sensitive = true
  value = {
    CS_WORKSPACE_CRN     = var.workspace_crn
    CS_CLIENT_ID         = cipherstash_zerokms_client.invoices_api.id
    CS_CLIENT_KEY        = cipherstash_zerokms_client.invoices_api.client_key
    CS_CLIENT_ACCESS_KEY = cipherstash_cts_actor.invoices_api.access_key
  }
}
```

Apply the change:

```shell
terraform plan -out=invoices.tfplan && \
  terraform apply invoices.tfplan
```

The plan should end with `Plan: 1 to add, 0 to change, 0 to destroy.` The provider runs the whole installation in one transaction. If anything goes wrong, such as the role lacking permission to create EQL's index support, it rolls back and the database is left unchanged.

Check that EQL is installed:

```shell
docker exec invoices-postgres \
  psql --username=postgres --dbname=invoices \
  --tuples-only --no-align --command='SELECT eql_v4.version();'
```

It should print `go-0.1.0-rc.3`. To see what EQL adds, create a table with an encrypted column. The `public.eql_v4_text_eq` type holds an encrypted string that can be compared for equality:

```shell
docker exec invoices-postgres \
  psql --username=postgres --dbname=invoices \
  --command='CREATE TABLE invoices (invoice_number bigint PRIMARY KEY, customer_email public.eql_v4_text_eq);'
```

PostgreSQL prints `CREATE TABLE`. The invoices service would encrypt each email address with CipherStash before inserting it, so the database only ever stores ciphertext.

## Let the invoices service's database role use EQL

So far you've used the database superuser. The invoices service should connect as its own role, and that role needs permission to use EQL's two schemas. The CipherStash provider leaves database roles and grants to the community PostgreSQL provider, `cyrilgdn/postgresql`, which you add in this step.

Pick a password for the service's role:

```shell
# Password for the invoices service's database role. Any value works.
export INVOICES_APP_PASSWORD='quiet-harbor-91' && \
  export TF_VAR_invoices_app_password="${INVOICES_APP_PASSWORD?}"
```

Replace the contents of `invoices-infra/main.tf` with the following. It adds the PostgreSQL provider, an `invoices_app` role, and grants on both EQL schemas. This is also the [complete example](https://github.com/cipherstash/terraform-provider-cipherstash/tree/main/examples/eql-quickstart) in the provider's repository.

```terraform
# invoices-infra/main.tf
terraform {
  required_version = "~> 1.14.0"

  required_providers {
    cipherstash = {
      source  = "terraform.local/cipherstash/cipherstash"
      version = "0.0.1"
    }
    postgresql = {
      source  = "cyrilgdn/postgresql"
      version = "1.27.0"
    }
  }
}

variable "workspace_crn" {
  type = string
}

variable "invoices_app_password" {
  type      = string
  sensitive = true
}

provider "cipherstash" {
  # Connect to CipherStash. The Admin access key comes from CS_CLIENT_ACCESS_KEY.
  auth = {
    workspace_crn = var.workspace_crn
  }

  # Connect to PostgreSQL. The password comes from PGPASSWORD.
  database = {
    host     = "localhost"
    port     = 5432
    username = "postgres"
    sslmode  = "disable" # The local container has no TLS. Use "verify-full" in production.
  }
}

# The community PostgreSQL provider, for roles and grants. It also reads PGPASSWORD.
provider "postgresql" {
  host     = "localhost"
  port     = 5432
  username = "postgres"
  sslmode  = "disable"
}

resource "cipherstash_zerokms_keyset" "invoices" {
  name        = "invoices"
  description = "Customer invoices"
}

resource "cipherstash_zerokms_client" "invoices_api" {
  name        = "invoices-api"
  description = "Invoices API service"
}

resource "cipherstash_zerokms_keyset_grant" "invoices_api" {
  client_id = cipherstash_zerokms_client.invoices_api.id
  keyset_id = cipherstash_zerokms_keyset.invoices.id
}

resource "cipherstash_cts_actor" "invoices_api" {
  name = "invoices-api"
  role = "member"
}

resource "cipherstash_eql_v4" "invoices" {
  database = "invoices"
  version  = "go-0.1.0-rc.3"
}

# The role the invoices service connects as.
resource "postgresql_role" "invoices_app" {
  name     = "invoices_app"
  login    = true
  password = var.invoices_app_password
}

# Let the role use both EQL schemas. EQL's functions run with the caller's
# permissions and reach into eql_v4_internal, so the role needs both.
# Referring to the EQL resource's schema names makes Terraform install EQL
# before granting on its schemas.
resource "postgresql_grant" "invoices_app_eql" {
  for_each = toset([
    cipherstash_eql_v4.invoices.schema,
    cipherstash_eql_v4.invoices.internal_schema,
  ])

  database    = "invoices"
  role        = postgresql_role.invoices_app.name
  schema      = each.key
  object_type = "schema"
  privileges  = ["USAGE"]
}

output "app_environment" {
  sensitive = true
  value = {
    CS_WORKSPACE_CRN     = var.workspace_crn
    CS_CLIENT_ID         = cipherstash_zerokms_client.invoices_api.id
    CS_CLIENT_KEY        = cipherstash_zerokms_client.invoices_api.client_key
    CS_CLIENT_ACCESS_KEY = cipherstash_cts_actor.invoices_api.access_key
  }
}
```

Download the new provider and apply:

```shell
terraform init && \
  terraform plan -out=invoices.tfplan && \
  terraform apply invoices.tfplan
```

The plan should end with `Plan: 3 to add, 0 to change, 0 to destroy.` The three are the role and one grant for each EQL schema.

Now connect as `invoices_app` and run the check from [What you'll build](#what-youll-build):

```shell
docker exec --env PGPASSWORD="${INVOICES_APP_PASSWORD?}" invoices-postgres \
  psql --host=127.0.0.1 --username=invoices_app --dbname=invoices \
  --tuples-only --no-align --command='SELECT eql_v4.version();'
```

It should print `go-0.1.0-rc.3`. Without the grants, the same command fails with `permission denied for schema eql_v4`.

The invoices service now has everything it needs: the four `CS_*` variables to reach CipherStash, and a database role that can use EQL. The file from this step is the complete configuration.

## Clean up

Destroy everything Terraform created, then remove the container:

```shell
terraform destroy -auto-approve && \
  docker rm --force invoices-postgres
```

Destroying revokes the grants, drops the `invoices_app` role and uninstalls EQL, which works because no table uses EQL's types. It also deletes the actor, its access key, the client and the keyset grant. The keyset itself can't be deleted, so Terraform disables it and leaves it in your workspace.
