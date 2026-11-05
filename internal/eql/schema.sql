-- The objects queries.sql refers to outside PostgreSQL's system catalogs, so
-- that sqlc can check those queries. Every EQL v4 installer creates them. This
-- file is never run against a database.
CREATE SCHEMA eql_v4;
CREATE FUNCTION eql_v4.version() RETURNS text LANGUAGE sql AS $$SELECT ''$$;
