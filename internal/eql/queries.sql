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

-- name: ObjectsNotOwned :many
-- The EQL objects Uninstall drops by name that the role lacks the privileges
-- of the owner for. Dropping a schema with CASCADE needs ownership of the
-- schema only, not of what it contains.
SELECT pg_describe_object(o.classid, o.objid, 0)::text
FROM (
  SELECT 'pg_namespace'::regclass AS classid, oid AS objid, nspowner AS owner
  FROM pg_catalog.pg_namespace WHERE nspname IN ('eql_v4', 'eql_v4_internal')
  UNION ALL
  SELECT 'pg_type'::regclass, oid, typowner FROM pg_catalog.pg_type
  WHERE typnamespace = 'public'::regnamespace AND typtype = 'd' AND typname LIKE 'eql\_v4\_%'
  UNION ALL
  SELECT 'pg_proc'::regclass, oid, proowner FROM pg_catalog.pg_proc
  WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'eql\_v4\_%'
) o
WHERE NOT pg_has_role(o.owner, 'USAGE')
ORDER BY 1;

-- name: ColumnsUsingDomains :many
-- Columns typed with an EQL domain in public, or an array of one, in tables,
-- partitioned tables, views, materialized views, foreign tables and composite
-- types. Without EQL those columns either reject writes or compare whole
-- ciphertexts.
SELECT pg_describe_object('pg_class'::regclass, c.oid, a.attnum)::text
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'c') AND a.attnum > 0 AND NOT a.attisdropped
  AND EXISTS (
    SELECT FROM pg_catalog.pg_type d
    WHERE d.oid IN (t.oid, t.typelem) AND d.typnamespace = 'public'::regnamespace
      AND d.typtype = 'd' AND d.typname LIKE 'eql\_v4\_%')
ORDER BY 1;

-- name: Dependents :many
-- The objects outside EQL that dropping both EQL schemas with CASCADE would
-- drop. It follows pg_depend from the two schemas, and from part of an object,
-- such as a view's rule, to the whole object, and names whole objects only. It
-- ignores what the installer itself creates outside the schemas: operators
-- whose function is in an EQL schema, and the eql_ore_unavailable constraints
-- it adds to the domains in public without the ORE operator class. It also
-- ignores default privileges in the schemas, which are grants rather than
-- objects that use EQL. For an index that an upgrade can rebuild, it also
-- returns the index's name.
WITH RECURSIVE eql AS (
  SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('eql_v4', 'eql_v4_internal')
), dependents(classid, objid, objsubid) AS (
  SELECT d.classid, d.objid, d.objsubid FROM pg_catalog.pg_depend d
  WHERE d.refclassid = 'pg_namespace'::regclass AND d.refobjid IN (SELECT oid FROM eql)
  UNION
  SELECT n.* FROM dependents x CROSS JOIN LATERAL (
    SELECT d.classid, d.objid, d.objsubid FROM pg_catalog.pg_depend d
    WHERE d.refclassid = x.classid AND d.refobjid = x.objid AND (x.objsubid = 0 OR d.refobjsubid = x.objsubid)
    UNION ALL
    SELECT d.refclassid, d.refobjid, d.refobjsubid FROM pg_catalog.pg_depend d
    WHERE d.classid = x.classid AND d.objid = x.objid AND d.objsubid = x.objsubid AND d.deptype = 'i'
  ) n
), located AS (
  SELECT x.*, CASE x.classid
      WHEN 'pg_amop'::regclass THEN (
        SELECT f.opfnamespace FROM pg_catalog.pg_amop a
        JOIN pg_catalog.pg_opfamily f ON f.oid = a.amopfamily WHERE a.oid = x.objid)
      WHEN 'pg_amproc'::regclass THEN (
        SELECT f.opfnamespace FROM pg_catalog.pg_amproc a
        JOIN pg_catalog.pg_opfamily f ON f.oid = a.amprocfamily WHERE a.oid = x.objid)
      ELSE (SELECT oid FROM pg_catalog.pg_namespace
            WHERE nspname = (pg_identify_object(x.classid, x.objid, x.objsubid)).schema)
    END AS namespace
  FROM dependents x
)
SELECT DISTINCT pg_describe_object(x.classid, x.objid, x.objsubid)::text AS name,
  -- An upgrade can rebuild a plain index on a regular table. The query below
  -- re-creates one from pg_get_indexdef, which omits the tablespace and
  -- per-column statistics targets, so indexes with those are left out.
  COALESCE((
    SELECT i.indexrelid::regclass::text FROM pg_catalog.pg_index i
    JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid
    JOIN pg_catalog.pg_class t ON t.oid = i.indrelid
    WHERE x.classid = 'pg_class'::regclass AND x.objsubid = 0 AND i.indexrelid = x.objid
      AND ic.relkind = 'i' AND ic.reltablespace = 0
      AND t.relkind = 'r' AND t.relpersistence <> 't'
      AND NOT EXISTS (SELECT FROM pg_catalog.pg_attribute a WHERE a.attrelid = i.indexrelid AND a.attstattarget >= 0)
  ), '')::text AS rebuildable_index
FROM located x
WHERE NOT EXISTS (SELECT FROM eql WHERE eql.oid = x.namespace)
  AND x.namespace IS DISTINCT FROM 'pg_toast'::regnamespace
  AND x.classid <> 'pg_default_acl'::regclass
  AND NOT (x.classid = 'pg_operator'::regclass AND EXISTS (
    SELECT FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_proc p ON p.oid = o.oprcode
    WHERE o.oid = x.objid AND p.pronamespace IN (SELECT oid FROM eql)))
  AND NOT (x.classid = 'pg_constraint'::regclass AND EXISTS (
    SELECT FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_type t ON t.oid = c.contypid
    WHERE c.oid = x.objid AND c.conname = 'eql_ore_unavailable'
      AND t.typnamespace = 'public'::regnamespace AND t.typname LIKE 'eql\_v4\_%'))
  AND NOT EXISTS (
    SELECT FROM pg_catalog.pg_depend d
    JOIN located y ON y.classid = d.refclassid AND y.objid = d.refobjid AND y.objsubid = d.refobjsubid
    WHERE d.classid = x.classid AND d.objid = x.objid AND d.objsubid = x.objsubid AND d.deptype = 'i')
ORDER BY 1;

-- name: DropLeftovers :exec
-- Drops what the uninstaller leaves in public: the column domains, then the
-- functions two of their CHECKs call. Without CASCADE, anything else that
-- still depends on one fails the statement instead of being dropped with it.
DO $$
DECLARE
  domains text;
  functions text;
BEGIN
  SELECT string_agg(format('public.%I', typname), ', ') INTO domains FROM pg_catalog.pg_type
  WHERE typnamespace = 'public'::regnamespace AND typtype = 'd' AND typname LIKE 'eql\_v4\_%';
  IF domains IS NOT NULL THEN
    EXECUTE 'DROP DOMAIN ' || domains;
  END IF;

  SELECT string_agg(oid::regprocedure::text, ', ') INTO functions FROM pg_catalog.pg_proc
  WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'eql\_v4\_%';
  IF functions IS NOT NULL THEN
    EXECUTE 'DROP FUNCTION ' || functions;
  END IF;
END
$$;

-- name: AnyEQLObjectRemains :one
SELECT (to_regnamespace('eql_v4') IS NOT NULL OR to_regnamespace('eql_v4_internal') IS NOT NULL
    OR EXISTS (SELECT FROM pg_catalog.pg_type WHERE typnamespace = 'public'::regnamespace AND typname LIKE 'eql\_v4\_%')
    OR EXISTS (SELECT FROM pg_catalog.pg_proc WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'eql\_v4\_%'))::boolean;

-- name: NotOwnedForUpgrade :many
-- Besides the objects ObjectsNotOwned lists, an upgrade re-creates indexes,
-- which needs the privileges of their table's owner, and restores default
-- privileges, which needs the privileges of the role they belong to.
SELECT o.name FROM (
  SELECT pg_describe_object('pg_class'::regclass, i.indrelid, 0)::text AS name, t.relowner AS owner
  FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class t ON t.oid = i.indrelid
  WHERE i.indexrelid IN (SELECT to_regclass(n) FROM unnest(sqlc.arg(indexes)::text[]) n)
  UNION
  SELECT pg_describe_object('pg_default_acl'::regclass, d.oid, 0)::text, d.defaclrole
  FROM pg_catalog.pg_default_acl d
  WHERE d.defaclnamespace IN (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('eql_v4', 'eql_v4_internal'))
) o
WHERE NOT pg_has_role(o.owner, 'USAGE')
ORDER BY 1;

-- name: Indexes :many
-- Each named index as statements that re-create it, with its comment and
-- CLUSTER mark, plus its operator classes, which pg_get_indexdef omits when
-- they are the default. Comparing the rows from before and after a rebuild
-- shows whether it re-created the same indexes.
SELECT i.indexrelid::regclass::text AS name,
       pg_get_indexdef(i.indexrelid)::text AS definition,
       COALESCE((SELECT string_agg(format('%I.%I', n.nspname, c.opcname), ' ' ORDER BY k.ord)
                 FROM unnest(i.indclass::oid[]) WITH ORDINALITY AS k(oid, ord)
                 JOIN pg_catalog.pg_opclass c ON c.oid = k.oid
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.opcnamespace), '')::text AS operator_classes,
       COALESCE((SELECT format('COMMENT ON INDEX %s IS %L', i.indexrelid::regclass, d.description)
                 FROM pg_catalog.pg_description d
                 WHERE d.classoid = 'pg_class'::regclass AND d.objoid = i.indexrelid AND d.objsubid = 0), '')::text AS comment,
       (CASE WHEN i.indisclustered
             THEN format('ALTER TABLE %s CLUSTER ON %I', i.indrelid::regclass, ic.relname) ELSE '' END)::text AS cluster,
       format('ANALYZE %s', i.indrelid::regclass)::text AS analyze_table
FROM pg_catalog.pg_index i
JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid
WHERE i.indexrelid IN (SELECT to_regclass(n) FROM unnest(sqlc.arg(names)::text[]) n)
ORDER BY 1;

-- name: LockTables :one
-- A statement that locks the tables of the named indexes as dropping the
-- indexes would, or an empty string when there are none. Queries lock a table
-- before its indexes, but the installer's DROP SCHEMA CASCADE locks each index
-- before its table, so taking the tables first keeps the two from deadlocking.
SELECT COALESCE('LOCK TABLE ' || string_agg(t, ', ' ORDER BY t) || ' IN ACCESS EXCLUSIVE MODE', '')::text
FROM (SELECT DISTINCT i.indrelid::regclass::text AS t
      FROM pg_catalog.pg_index i
      WHERE i.indexrelid IN (SELECT to_regclass(n) FROM unnest(sqlc.arg(names)::text[]) n)) tables;

-- name: SchemaGrants :many
-- The grants on the EQL schemas, other than their owner's own, as statements
-- that restore them.
SELECT format('GRANT %s ON SCHEMA %I TO %s%s', a.privilege_type, n.nspname,
              CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(a.grantee)) END,
              CASE WHEN a.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END)::text
FROM pg_catalog.pg_namespace n
CROSS JOIN LATERAL aclexplode(n.nspacl) a
WHERE n.nspname IN ('eql_v4', 'eql_v4_internal') AND a.grantee <> n.nspowner
ORDER BY 1;

-- name: ObjectGrants :many
-- The grants on the routines and types in the EQL schemas, other than their
-- owner's own, as statements that restore them, keyed by kind and name. An
-- object whose privileges were changed without a grant to PUBLIC also gets a
-- REVOKE, so that revoking PUBLIC's default EXECUTE or USAGE survives a
-- reinstall.
WITH eql AS (
  SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('eql_v4', 'eql_v4_internal')
), objects AS (
  SELECT 'routine'::text AS kind, p.oid::regprocedure::text AS name, 'ROUTINE'::text AS keyword,
         'EXECUTE'::text AS public_privilege, 'f'::"char" AS default_type, p.pronamespace AS namespace, p.proowner AS owner, p.proacl AS acl
  FROM pg_catalog.pg_proc p WHERE p.pronamespace IN (SELECT oid FROM eql)
  UNION ALL
  -- Array types take their element type's privileges.
  SELECT 'type', t.oid::regtype::text, 'TYPE', 'USAGE', 'T', t.typnamespace, t.typowner, t.typacl
  FROM pg_catalog.pg_type t WHERE t.typnamespace IN (SELECT oid FROM eql) AND t.typcategory <> 'A'
)
SELECT o.kind, o.name,
       format('GRANT %s ON %s %s TO %s%s', a.privilege_type, o.keyword, o.name,
              CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(a.grantee)) END,
              CASE WHEN a.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END)::text AS statement
FROM objects o
CROSS JOIN LATERAL aclexplode(o.acl) a
WHERE a.grantee <> o.owner
UNION ALL
SELECT o.kind, o.name, format('REVOKE %s ON %s %s FROM PUBLIC', o.public_privilege, o.keyword, o.name)::text
FROM objects o
WHERE o.acl IS NOT NULL AND NOT EXISTS (SELECT FROM aclexplode(o.acl) a WHERE a.grantee = 0)
ORDER BY 1, 2, 3;

-- name: EQLObjects :many
-- The routines and types in the EQL schemas.
WITH eql AS (
  SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('eql_v4', 'eql_v4_internal')
), objects AS (
  SELECT 'routine'::text AS kind, p.oid::regprocedure::text AS name, 'ROUTINE'::text AS keyword,
         'EXECUTE'::text AS public_privilege, 'f'::"char" AS default_type, p.pronamespace AS namespace, p.proowner AS owner, p.proacl AS acl
  FROM pg_catalog.pg_proc p WHERE p.pronamespace IN (SELECT oid FROM eql)
  UNION ALL
  -- Array types take their element type's privileges.
  SELECT 'type', t.oid::regtype::text, 'TYPE', 'USAGE', 'T', t.typnamespace, t.typowner, t.typacl
  FROM pg_catalog.pg_type t WHERE t.typnamespace IN (SELECT oid FROM eql) AND t.typcategory <> 'A'
)
SELECT o.kind, o.name FROM objects o ORDER BY 1, 2;

-- name: NewObjectGrants :many
-- What the default privileges in the EQL schemas grant on the routines and
-- types other than the named ones, as statements that apply them.
-- PostgreSQL applies the default privileges of the role that creates an
-- object, which owns it.
WITH eql AS (
  SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('eql_v4', 'eql_v4_internal')
), objects AS (
  SELECT 'routine'::text AS kind, p.oid::regprocedure::text AS name, 'ROUTINE'::text AS keyword,
         'EXECUTE'::text AS public_privilege, 'f'::"char" AS default_type, p.pronamespace AS namespace, p.proowner AS owner, p.proacl AS acl
  FROM pg_catalog.pg_proc p WHERE p.pronamespace IN (SELECT oid FROM eql)
  UNION ALL
  -- Array types take their element type's privileges.
  SELECT 'type', t.oid::regtype::text, 'TYPE', 'USAGE', 'T', t.typnamespace, t.typowner, t.typacl
  FROM pg_catalog.pg_type t WHERE t.typnamespace IN (SELECT oid FROM eql) AND t.typcategory <> 'A'
)
SELECT format('GRANT %s ON %s %s TO %s%s', a.privilege_type, o.keyword, o.name,
              CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(a.grantee)) END,
              CASE WHEN a.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END)::text
FROM objects o
JOIN pg_catalog.pg_default_acl d
  ON d.defaclnamespace = o.namespace AND d.defaclrole = o.owner AND d.defaclobjtype = o.default_type
CROSS JOIN LATERAL aclexplode(d.defaclacl) a
WHERE NOT (o.kind = 'routine' AND o.name = ANY (sqlc.arg(routines)::text[]))
  AND NOT (o.kind = 'type' AND o.name = ANY (sqlc.arg(types)::text[]))
ORDER BY 1;

-- name: DefaultPrivileges :many
-- The default privileges in the EQL schemas as statements that restore them.
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT %s ON %s TO %s%s',
              pg_get_userbyid(d.defaclrole), n.nspname, a.privilege_type,
              CASE d.defaclobjtype WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES' WHEN 'f' THEN 'ROUTINES' WHEN 'T' THEN 'TYPES' END,
              CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(a.grantee)) END,
              CASE WHEN a.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END)::text
FROM pg_catalog.pg_default_acl d
JOIN pg_catalog.pg_namespace n ON n.oid = d.defaclnamespace
CROSS JOIN LATERAL aclexplode(d.defaclacl) a
WHERE n.nspname IN ('eql_v4', 'eql_v4_internal')
ORDER BY 1;

-- name: MissingObjects :many
-- The named routines and types that do not exist, each as its kind and name.
SELECT ('routine ' || r)::text FROM unnest(sqlc.arg(routines)::text[]) r WHERE to_regprocedure(r) IS NULL
UNION
SELECT ('type ' || t)::text FROM unnest(sqlc.arg(types)::text[]) t WHERE to_regtype(t) IS NULL
ORDER BY 1;
