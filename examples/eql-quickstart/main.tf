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
