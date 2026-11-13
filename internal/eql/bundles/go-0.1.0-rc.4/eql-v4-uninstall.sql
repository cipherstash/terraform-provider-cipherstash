-- Uninstall the standalone eql_v4 surface. CASCADE removes the domains, SEM
-- types, operators, opclass, and any columns typed with the eql_v4 domains.
DROP SCHEMA IF EXISTS eql_v4 CASCADE;

-- Drop the internal implementation schema after eql_v4 (eql_v4's extractors and
-- operators depend on eql_v4_internal types; dropping eql_v4 first with CASCADE
-- removes those dependents, then eql_v4_internal drops cleanly).
DROP SCHEMA IF EXISTS eql_v4_internal CASCADE;
