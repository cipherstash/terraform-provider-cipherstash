-- sqlc generates internal/db from these queries. System catalogs are
-- qualified with pg_catalog and results are cast, so sqlc can type them.

-- name: TryLifecycleLock :one
-- The same advisory lock key as the stash CLI's EQL installer, so the two
-- never install concurrently.
SELECT pg_try_advisory_xact_lock(hashtext('cipherstash.eql.lifecycle'))::boolean;

-- name: ConfigureTransaction :exec
-- The installer creates its operators unqualified, in the first schema on
-- search_path, and its ORE operator class refers to them as public.<.
SELECT set_config('search_path', 'public', true),
       set_config('jit', 'off', true),
       set_config('lock_timeout', '5s', true),
       set_config('statement_timeout', '10min', true);

-- name: InspectSchemas :one
SELECT (to_regnamespace('eql_v4') IS NOT NULL)::boolean AS has_schema,
       (to_regnamespace('eql_v4_internal') IS NOT NULL)::boolean AS has_internal_schema,
       (to_regprocedure('eql_v4.version()') IS NOT NULL)::boolean AS has_version,
       COALESCE((SELECT n.nspname::text FROM pg_catalog.pg_extension e
                 JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
                 WHERE e.extname = 'pgcrypto'), '')::text AS pgcrypto_schema,
       COALESCE((SELECT nspowner::regrole::text FROM pg_catalog.pg_namespace
                 WHERE nspname = 'eql_v4'), '')::text AS owner;

-- name: InspectInstallation :one
SELECT eql_v4.version() AS version,
       (EXISTS (SELECT FROM pg_catalog.pg_opclass
                WHERE opcname = 'ore_block_v2_operator_class'
                  AND opcnamespace = 'eql_v4_internal'::regnamespace)
        AND NOT EXISTS (SELECT FROM pg_catalog.pg_constraint WHERE conname = 'eql_ore_unavailable'))::boolean AS ore_available;

-- name: CanCreate :one
SELECT (has_database_privilege(current_database(), 'CREATE') AND has_schema_privilege('public', 'CREATE'))::boolean;

-- name: SchemaComment :one
SELECT COALESCE(obj_description('eql_v4'::regnamespace, 'pg_namespace'), '')::text;
