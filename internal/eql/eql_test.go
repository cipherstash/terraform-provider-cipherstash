package eql

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestBundlesMatchDigests(t *testing.T) {
	dirs, err := fs.ReadDir(bundles, "bundles")
	require.NoError(t, err)

	embedded := map[string]bool{}
	for _, dir := range dirs {
		r, i := lookup(dir.Name())
		require.GreaterOrEqual(t, i, 0, "bundles/%s has no manifest entry", dir.Name())

		for name, digest := range map[string]string{"eql-v4-install.sql": r.InstallSQLSHA256, "eql-v4-uninstall.sql": r.UninstallSQLSHA256} {
			script, err := bundles.ReadFile(path.Join("bundles", dir.Name(), name))
			require.NoError(t, err)

			sum := sha256.Sum256(script)
			require.Equal(t, digest, hex.EncodeToString(sum[:]), "bundles/%s/%s does not match its digest", dir.Name(), name)
		}

		embedded[dir.Name()] = true
	}

	for _, version := range Versions() {
		require.True(t, embedded[version], "digest for %s has no bundle", version)
	}
}

// The tests below need a PostgreSQL superuser connection in
// CS_TEST_POSTGRES_URL. Each creates its own database and roles.

func adminConfig(t *testing.T) *pgx.ConnConfig {
	t.Helper()

	url := os.Getenv("CS_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("CS_TEST_POSTGRES_URL is not set")
	}

	config, err := pgx.ParseConfig(url)
	require.NoError(t, err)

	return config
}

func connect(t *testing.T, config *pgx.ConnConfig) *pgx.Conn {
	t.Helper()

	conn, err := pgx.ConnectConfig(t.Context(), config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	return conn
}

func exec(t *testing.T, conn *pgx.Conn, sql string) {
	t.Helper()

	_, err := conn.Exec(t.Context(), sql)
	require.NoError(t, err, sql)
}

func randomName(t *testing.T, prefix string) string {
	t.Helper()

	suffix := make([]byte, 6)
	_, err := rand.Read(suffix)
	require.NoError(t, err)

	return prefix + "_" + hex.EncodeToString(suffix)
}

// testDatabase creates an empty database and returns a superuser connection
// configuration for it.
func testDatabase(t *testing.T) *pgx.ConnConfig {
	t.Helper()

	admin := adminConfig(t)
	name := randomName(t, "eql_test")
	conn := connect(t, admin)
	exec(t, conn, "CREATE DATABASE "+name)
	// t.Context is cancelled before cleanups run.
	t.Cleanup(func() {
		cleanup, err := pgx.ConnectConfig(context.Background(), admin)
		require.NoError(t, err)
		defer func() { _ = cleanup.Close(context.Background()) }()

		_, err = cleanup.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		require.NoError(t, err)
	})

	config := admin.Copy()
	config.Database = name

	return config
}

// testRole creates a login role that is not a superuser and can create
// objects in the database, including the trusted pgcrypto extension.
func testRole(t *testing.T, database *pgx.ConnConfig) *pgx.ConnConfig {
	t.Helper()

	name := randomName(t, "eql_role")
	password := randomName(t, "password")
	conn := connect(t, database)
	exec(t, conn, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", name, password))
	exec(t, conn, fmt.Sprintf("GRANT CREATE ON DATABASE %s TO %s", database.Database, name))
	exec(t, conn, "GRANT CREATE ON SCHEMA public TO "+name)
	// Runs before the database is dropped, so the role's objects and
	// privileges there must go first.
	t.Cleanup(func() {
		cleanup, err := pgx.ConnectConfig(context.Background(), database)
		require.NoError(t, err)
		defer func() { _ = cleanup.Close(context.Background()) }()

		_, err = cleanup.Exec(context.Background(), "DROP OWNED BY "+name+"; DROP ROLE "+name)
		require.NoError(t, err)
	})

	config := database.Copy()
	config.User, config.Password = name, password

	return config
}

const version = "go-0.1.0-rc.4"

func TestPostgresInstallAndInspect(t *testing.T) {
	database := testDatabase(t)
	conn := connect(t, database)

	before, err := Inspect(t.Context(), conn)
	require.NoError(t, err)
	require.Equal(t, Installation{}, before)

	require.NoError(t, Install(t.Context(), conn, version, true))

	after, err := Inspect(t.Context(), conn)
	require.NoError(t, err)
	require.Equal(t, Installation{
		Installed:      true,
		Version:        version,
		Owner:          database.User,
		OREAvailable:   true,
		PgcryptoSchema: "extensions",
	}, after)

	// A second install would drop both schemas, and every grant and index on
	// them, so it is refused before anything changes.
	err = Install(t.Context(), conn, version, true)
	require.ErrorIs(t, err, ErrAlreadyInstalled)
	require.True(t, Refused(err))
}

func TestPostgresInstallKeepsPgcryptoInPublic(t *testing.T) {
	database := testDatabase(t)
	conn := connect(t, database)
	exec(t, conn, "CREATE EXTENSION pgcrypto SCHEMA public")

	require.NoError(t, Install(t.Context(), conn, version, true))

	after, err := Inspect(t.Context(), conn)
	require.NoError(t, err)
	require.Equal(t, "public", after.PgcryptoSchema)
	require.True(t, after.OREAvailable)
}

func TestPostgresInstallWithoutSuperuser(t *testing.T) {
	database := testDatabase(t)
	role := testRole(t, database)
	conn := connect(t, role)

	// The installer succeeds without the ORE operator class, so the check
	// after it must roll the whole installation back.
	err := Install(t.Context(), conn, version, true)
	require.ErrorIs(t, err, ErrOREUnavailable)

	after, err := Inspect(t.Context(), conn)
	require.NoError(t, err)
	require.False(t, after.Installed, "a refused installation left EQL behind")
	require.Empty(t, after.PgcryptoSchema, "a refused installation left pgcrypto behind")

	require.NoError(t, Install(t.Context(), conn, version, false))

	after, err = Inspect(t.Context(), conn)
	require.NoError(t, err)
	require.True(t, after.Installed)
	require.False(t, after.OREAvailable)
	require.Equal(t, role.User, after.Owner)

	// The role owns everything it installed, and the uninstaller's CASCADE
	// removes the eql_ore_unavailable constraints from the domains in public.
	require.NoError(t, Uninstall(t.Context(), conn))

	after, err = Inspect(t.Context(), conn)
	require.NoError(t, err)
	require.False(t, after.Installed)
}

func TestPostgresInstallRefusals(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn
		want  error
	}{
		{
			name: "existing eql_v4 schema",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				conn := connect(t, database)
				exec(t, conn, "CREATE SCHEMA eql_v4")

				return conn
			},
			want: ErrAlreadyInstalled,
		},
		{
			name: "existing eql_v4_internal schema",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				conn := connect(t, database)
				exec(t, conn, "CREATE SCHEMA eql_v4_internal")

				return conn
			},
			want: ErrAlreadyInstalled,
		},
		{
			name: "pgcrypto in another schema",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				conn := connect(t, database)
				exec(t, conn, "CREATE SCHEMA crypto")
				exec(t, conn, "CREATE EXTENSION pgcrypto SCHEMA crypto")

				return conn
			},
			want: ErrPgcryptoSchema,
		},
		{
			name: "lock held by another session",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				holder := connect(t, database)
				exec(t, holder, "SELECT pg_advisory_lock(hashtext('cipherstash.eql.lifecycle'))")

				return connect(t, database)
			},
			want: ErrLocked,
		},
		{
			name: "no CREATE on public",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				role := testRole(t, database)
				exec(t, connect(t, database), "REVOKE CREATE ON SCHEMA public FROM "+role.User)

				return connect(t, role)
			},
			want: ErrPrivilege,
		},
		{
			name: "unknown version",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				return connect(t, database)
			},
			want: ErrUnknownVersion,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := testDatabase(t)
			conn := test.setup(t, database)
			before := snapshot(t, database)

			installVersion := version
			if test.want == ErrUnknownVersion {
				installVersion = "go-0.0.0"
			}

			err := Install(t.Context(), conn, installVersion, true)
			require.ErrorIs(t, err, test.want)
			require.True(t, Refused(err))
			require.Equal(t, before, snapshot(t, database), "a refused installation changed the database")
		})
	}
}

func TestPostgresInspectPartialInstallation(t *testing.T) {
	database := testDatabase(t)
	conn := connect(t, database)
	exec(t, conn, "CREATE SCHEMA eql_v4")
	exec(t, conn, "CREATE SCHEMA eql_v4_internal")

	_, err := Inspect(t.Context(), conn)
	require.ErrorIs(t, err, ErrPartial)
}

// snapshot lists the database's schemas, extensions, and its functions,
// operators, types and relations outside the system schemas.
func snapshot(t *testing.T, database *pgx.ConnConfig) []string {
	t.Helper()

	rows, err := connect(t, database).Query(t.Context(), `
WITH user_namespace AS (
  SELECT oid FROM pg_namespace WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
)
SELECT 'schema ' || nspname FROM pg_namespace
UNION ALL SELECT 'extension ' || extname FROM pg_extension
UNION ALL SELECT 'function ' || oid::regprocedure::text FROM pg_proc WHERE pronamespace IN (SELECT oid FROM user_namespace)
UNION ALL SELECT 'operator ' || oid::regoperator::text FROM pg_operator WHERE oprnamespace IN (SELECT oid FROM user_namespace)
UNION ALL SELECT 'type ' || oid::regtype::text FROM pg_type WHERE typnamespace IN (SELECT oid FROM user_namespace)
UNION ALL SELECT 'relation ' || oid::regclass::text FROM pg_class WHERE relnamespace IN (SELECT oid FROM user_namespace)
ORDER BY 1`)
	require.NoError(t, err)

	objects, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)

	return objects
}

func TestPostgresUninstall(t *testing.T) {
	for _, installed := range Versions() {
		t.Run(installed, func(t *testing.T) {
			database := testDatabase(t)
			conn := connect(t, database)
			exec(t, conn, "CREATE EXTENSION pgcrypto SCHEMA public")
			// The installer always creates schema extensions, which, like
			// pgcrypto, other code may use.
			exec(t, conn, "CREATE SCHEMA extensions")
			clean := snapshot(t, database)

			require.NoError(t, Install(t.Context(), conn, installed, true))
			// Grants, including default privileges, go with the schemas.
			app := testRole(t, database).User
			exec(t, conn, "GRANT USAGE ON SCHEMA eql_v4, eql_v4_internal TO "+app)
			exec(t, conn, "ALTER DEFAULT PRIVILEGES IN SCHEMA eql_v4 GRANT EXECUTE ON FUNCTIONS TO "+app)
			require.NoError(t, Uninstall(t.Context(), conn))
			// Beyond the uninstaller's schemas, this removes the domains and
			// functions it leaves in public.
			require.Equal(t, clean, snapshot(t, database), "uninstalling left objects behind or removed others")

			require.NoError(t, Uninstall(t.Context(), conn), "uninstalling without EQL must change nothing")
			require.Equal(t, clean, snapshot(t, database))

			// The domains are gone, so a new installation creates them with its own rules.
			require.NoError(t, Install(t.Context(), conn, version, true))
			after, err := Inspect(t.Context(), conn)
			require.NoError(t, err)
			require.Equal(t, version, after.Version)
		})
	}
}

// withSQL is a refusal setup that runs statements as the superuser.
func withSQL(statements string) func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
	return func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
		t.Helper()

		conn := connect(t, database)
		exec(t, conn, statements)

		return conn
	}
}

func TestPostgresUninstallRefusals(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn
		want  error
		named string
	}{
		// Columns using the domains in public, which the uninstaller keeps.
		{
			name:  "table column",
			setup: withSQL("CREATE TABLE encrypted (email public.eql_v4_text_eq)"),
			want:  ErrInUse,
			named: "column email of table encrypted",
		},
		{
			name:  "array column in a view",
			setup: withSQL("CREATE VIEW emails AS SELECT ARRAY[NULL::public.eql_v4_text_eq] AS emails"),
			want:  ErrInUse,
			named: "column emails of view emails",
		},
		{
			name:  "partitioned table column",
			setup: withSQL("CREATE TABLE events (email public.eql_v4_text_eq, at date) PARTITION BY RANGE (at)"),
			want:  ErrInUse,
			named: "column email of table events",
		},
		{
			name:  "materialized view column",
			setup: withSQL("CREATE MATERIALIZED VIEW emails AS SELECT NULL::public.eql_v4_text_eq AS email"),
			want:  ErrInUse,
			named: "column email of materialized view emails",
		},
		{
			name: "foreign table column",
			setup: withSQL(`CREATE FOREIGN DATA WRAPPER placeholder;
CREATE SERVER elsewhere FOREIGN DATA WRAPPER placeholder;
CREATE FOREIGN TABLE remote (email public.eql_v4_text_eq) SERVER elsewhere`),
			want:  ErrInUse,
			named: "column email of foreign table remote",
		},
		{
			name:  "composite type attribute",
			setup: withSQL("CREATE TYPE contact AS (email public.eql_v4_text_eq)"),
			want:  ErrInUse,
			named: "column email of composite type contact",
		},
		// Objects outside EQL that the uninstaller's CASCADE would drop.
		{
			name: "view on a view calling EQL",
			setup: withSQL(`CREATE VIEW eql_release AS SELECT eql_v4.version() AS version;
CREATE VIEW release_copy AS SELECT * FROM eql_release`),
			want:  ErrDependents,
			named: "view release_copy",
		},
		{
			name:  "materialized view calling EQL",
			setup: withSQL("CREATE MATERIALIZED VIEW eql_release AS SELECT eql_v4.version() AS version"),
			want:  ErrDependents,
			named: "materialized view eql_release",
		},
		{
			name:  "view using an EQL operator",
			setup: withSQL("CREATE VIEW same AS SELECT NULL::public.eql_v4_text_eq = NULL::public.eql_v4_text_eq AS same"),
			want:  ErrDependents,
			named: "view same",
		},
		{
			name:  "column typed with an EQL schema type",
			setup: withSQL("CREATE TABLE terms (term eql_v4.query_text_eq)"),
			want:  ErrDependents,
			named: "column term of table terms",
		},
		{
			name: "index calling EQL",
			setup: withSQL(`CREATE TABLE payloads (payload jsonb);
CREATE INDEX payloads_ord ON payloads (eql_v4.ord_term(payload::public.eql_v4_bigint_ord))`),
			want:  ErrDependents,
			named: "index payloads_ord",
		},
		{
			name:  "CHECK constraint calling EQL",
			setup: withSQL("CREATE TABLE releases (id int CONSTRAINT has_eql CHECK (eql_v4.version() IS NOT NULL))"),
			want:  ErrDependents,
			named: "constraint has_eql on table releases",
		},
		{
			name: "policy calling EQL",
			setup: withSQL(`CREATE TABLE releases (id int);
CREATE POLICY has_eql ON releases USING (eql_v4.version() IS NOT NULL)`),
			want:  ErrDependents,
			named: "policy has_eql on table releases",
		},
		{
			name:  "generated column calling EQL",
			setup: withSQL("CREATE TABLE releases (id int, version text GENERATED ALWAYS AS (eql_v4.version()) STORED)"),
			want:  ErrDependents,
			named: "column version of table releases",
		},
		{
			name:  "SQL function body calling EQL",
			setup: withSQL("CREATE FUNCTION release() RETURNS text LANGUAGE sql BEGIN ATOMIC SELECT eql_v4.version(); END"),
			want:  ErrDependents,
			named: "function release()",
		},
		{
			name: "role that does not own EQL",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				role := testRole(t, database)
				exec(t, connect(t, database), "GRANT USAGE ON SCHEMA eql_v4, eql_v4_internal TO "+role.User)

				return connect(t, role)
			},
			want:  ErrNotOwner,
			named: "schema eql_v4",
		},
		{
			name:  "installed version without an uninstaller",
			setup: withSQL("CREATE OR REPLACE FUNCTION eql_v4.version() RETURNS text IMMUTABLE STRICT LANGUAGE sql AS $$SELECT 'go-0.0.0'$$"),
			want:  ErrNoUninstaller,
		},
		{
			name: "lock held by another session",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				holder := connect(t, database)
				exec(t, holder, "SELECT pg_advisory_lock(hashtext('cipherstash.eql.lifecycle'))")

				return connect(t, database)
			},
			want: ErrLocked,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := testDatabase(t)
			require.NoError(t, Install(t.Context(), connect(t, database), version, true))
			conn := test.setup(t, database)
			before := snapshot(t, database)

			err := Uninstall(t.Context(), conn)
			require.ErrorIs(t, err, test.want)
			require.True(t, Refused(err))
			if test.named != "" {
				objects, ok := errors.AsType[*ObjectsError](err)
				require.True(t, ok, "the refusal names no objects")
				require.Contains(t, objects.Names, test.named)
			}

			require.Equal(t, before, snapshot(t, database), "a refused uninstall changed the database")
		})
	}
}

func TestPostgresUninstallFailsOnLeftoverDependents(t *testing.T) {
	database := testDatabase(t)
	conn := connect(t, database)
	require.NoError(t, Install(t.Context(), conn, version, true))
	// The scan follows dependencies on the EQL schemas only. This function
	// depends on a domain in public, so dropping the domain without CASCADE
	// fails and the whole uninstall rolls back.
	exec(t, conn, "CREATE FUNCTION email_length(email public.eql_v4_text_eq) RETURNS int LANGUAGE sql AS 'SELECT 1'")
	before := snapshot(t, database)

	err := Uninstall(t.Context(), conn)
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	require.True(t, ok, "%v", err)
	require.Equal(t, "2BP01", pgErr.Code)
	require.False(t, Refused(err))
	require.Equal(t, before, snapshot(t, database), "a failed uninstall changed the database")
}

func TestPostgresUninstallPartialInstallation(t *testing.T) {
	database := testDatabase(t)
	conn := connect(t, database)
	exec(t, conn, "CREATE SCHEMA eql_v4")

	require.ErrorIs(t, Uninstall(t.Context(), conn), ErrPartial)
}

func TestLater(t *testing.T) {
	versions := Versions()
	require.Equal(t, []string{"go-0.1.0-rc.3", "go-0.1.0-rc.4"}, versions, "versions follow releases.json")
	require.True(t, Later(versions[0], versions[1]))
	require.False(t, Later(versions[1], versions[0]), "downgrade")
	require.False(t, Later(versions[0], versions[0]), "same version")
	require.False(t, Later("go-0.0.0", versions[1]), "from a version that is not compiled in")
	require.False(t, Later(versions[0], "go-9.9.9"), "to a version that is not compiled in")
}

const upgradeFrom, upgradeTo = "go-0.1.0-rc.3", "go-0.1.0-rc.4"

// indexedTable creates a table with an index for each kind of query EQL
// documents, one with a comment and one marked for CLUSTER.
const indexedTable = `
CREATE TABLE encrypted (
  id         bigint PRIMARY KEY,
  email      public.eql_v4_text_eq,
  amount     public.eql_v4_bigint_ord,
  amount_ore public.eql_v4_bigint_ord_ore,
  name       public.eql_v4_text_match
);
CREATE INDEX encrypted_email_eq ON encrypted USING hash (eql_v4.eq_term(email));
CREATE INDEX encrypted_amount_ord ON encrypted USING btree (eql_v4.ord_term(amount));
CREATE INDEX encrypted_amount_ore ON encrypted USING btree (eql_v4.ord_term_ore(amount_ore));
CREATE INDEX encrypted_name_match ON encrypted USING gin (eql_v4.match_term(name));
COMMENT ON INDEX encrypted_email_eq IS 'equality on email';
ALTER TABLE encrypted CLUSTER ON encrypted_amount_ord;`

// indexes describes every index on table encrypted, including the operator
// classes that pg_get_indexdef omits when they are the default.
func indexes(t *testing.T, conn *pgx.Conn) []string {
	t.Helper()

	rows, err := conn.Query(t.Context(), `
SELECT pg_get_indexdef(i.indexrelid)
  || ' opclasses ' || (SELECT string_agg(c.opcname, ' ') FROM unnest(i.indclass::oid[]) o JOIN pg_opclass c ON c.oid = o)
  || ' comment ' || COALESCE(obj_description(i.indexrelid, 'pg_class'), '-') || ' clustered ' || i.indisclustered
FROM pg_index i WHERE i.indrelid = 'encrypted'::regclass ORDER BY 1`)
	require.NoError(t, err)
	described, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)

	return described
}

// privileges lists the explicit privileges on the EQL schemas, routines and
// types, and the default privileges in the schemas, each as its sorted ACL
// entries.
func privileges(t *testing.T, conn *pgx.Conn) map[string]string {
	t.Helper()

	rows, err := conn.Query(t.Context(), `
SELECT 'schema ' || nspname, (SELECT string_agg(a::text, ',' ORDER BY a::text) FROM unnest(nspacl) a) FROM pg_namespace
WHERE nspname IN ('eql_v4', 'eql_v4_internal') AND nspacl IS NOT NULL
UNION ALL
SELECT 'routine ' || oid::regprocedure::text, (SELECT string_agg(a::text, ',' ORDER BY a::text) FROM unnest(proacl) a) FROM pg_proc
WHERE pronamespace IN ('eql_v4'::regnamespace, 'eql_v4_internal'::regnamespace) AND proacl IS NOT NULL
UNION ALL
SELECT 'type ' || oid::regtype::text, (SELECT string_agg(a::text, ',' ORDER BY a::text) FROM unnest(typacl) a) FROM pg_type
WHERE typnamespace IN ('eql_v4'::regnamespace, 'eql_v4_internal'::regnamespace) AND typacl IS NOT NULL
UNION ALL
SELECT 'default ' || defaclrole::regrole::text || ' ' || defaclnamespace::regnamespace::text || ' ' || defaclobjtype::text, (SELECT string_agg(a::text, ',' ORDER BY a::text) FROM unnest(defaclacl) a)
FROM pg_default_acl WHERE defaclnamespace IN ('eql_v4'::regnamespace, 'eql_v4_internal'::regnamespace)`)
	require.NoError(t, err)

	listed := map[string]string{}
	for rows.Next() {
		var object, acl string
		require.NoError(t, rows.Scan(&object, &acl))
		listed[object] = acl
	}

	require.NoError(t, rows.Err())

	return listed
}

// eqlObjects lists the routines and types in the EQL schemas.
func eqlObjects(t *testing.T, conn *pgx.Conn) []string {
	t.Helper()

	rows, err := conn.Query(t.Context(), `
SELECT 'routine ' || oid::regprocedure::text FROM pg_proc WHERE pronamespace IN ('eql_v4'::regnamespace, 'eql_v4_internal'::regnamespace)
UNION ALL
SELECT 'type ' || oid::regtype::text FROM pg_type
WHERE typnamespace IN ('eql_v4'::regnamespace, 'eql_v4_internal'::regnamespace) AND typcategory <> 'A'`)
	require.NoError(t, err)
	listed, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)

	return listed
}

func TestPostgresUpgrade(t *testing.T) {
	database := testDatabase(t)
	conn := connect(t, database)
	require.NoError(t, Install(t.Context(), conn, upgradeFrom, true))
	exec(t, conn, indexedTable)
	app, outsider := testRole(t, database), testRole(t, database)
	exec(t, conn, fmt.Sprintf(`
GRANT USAGE ON SCHEMA eql_v4, eql_v4_internal TO %[1]s;
GRANT USAGE ON SCHEMA eql_v4 TO %[2]s;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA eql_v4, eql_v4_internal TO %[1]s WITH GRANT OPTION;
REVOKE EXECUTE ON FUNCTION eql_v4.version() FROM PUBLIC;
GRANT USAGE ON TYPE eql_v4.query_text_eq, eql_v4_internal.ore_block_v2 TO %[1]s;
REVOKE USAGE ON TYPE eql_v4.query_bigint_ord FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA eql_v4, eql_v4_internal GRANT EXECUTE ON FUNCTIONS TO %[1]s;
ALTER DEFAULT PRIVILEGES IN SCHEMA eql_v4, eql_v4_internal GRANT USAGE ON TYPES TO %[1]s;
ALTER DEFAULT PRIVILEGES FOR ROLE %[2]s IN SCHEMA eql_v4 GRANT EXECUTE ON FUNCTIONS TO %[2]s`, app.User, outsider.User))
	// rc.3 and rc.4 ship the same SQL, so the upgrade would neither add nor
	// remove a routine. Make it do both: drop one that the new release creates
	// again, and add one with a grant that the new release doesn't have.
	exec(t, conn, fmt.Sprintf(`
DROP ROUTINE eql_v4.grouped_value(jsonb);
CREATE FUNCTION eql_v4.retired() RETURNS int LANGUAGE sql AS 'SELECT 1';
GRANT EXECUTE ON FUNCTION eql_v4.retired() TO %s`, app.User))
	beforeIndexes, beforePrivileges, beforeObjects := indexes(t, conn), privileges(t, conn), eqlObjects(t, conn)

	report, err := Upgrade(t.Context(), conn, upgradeFrom, upgradeTo, true, true)
	require.NoError(t, err)

	after, err := Inspect(t.Context(), conn)
	require.NoError(t, err)
	require.Equal(t, upgradeTo, after.Version)
	require.True(t, after.OREAvailable)
	require.ElementsMatch(t, []string{"encrypted_email_eq", "encrypted_amount_ord", "encrypted_amount_ore", "encrypted_name_match"}, report.RebuiltIndexes)
	require.Equal(t, beforeIndexes, indexes(t, conn), "the upgrade changed an index")

	// Routines and types the new release doesn't have lose their grants; the
	// rest keep them exactly.
	require.Equal(t, []string{"routine eql_v4.retired()"}, report.RemovedObjects)
	for _, removed := range report.RemovedObjects {
		require.Contains(t, beforePrivileges, removed, "reported an object that had no grants")
		delete(beforePrivileges, removed)
	}

	afterPrivileges := privileges(t, conn)
	for object, acl := range beforePrivileges {
		require.Equal(t, acl, afterPrivileges[object], object)
	}

	// Routines and types new in the release get what the installing role's
	// default privileges grant, and not another role's.
	var added []string
	for _, object := range eqlObjects(t, conn) {
		if !slices.Contains(beforeObjects, object) {
			added = append(added, object)
		}
	}

	require.Equal(t, []string{"routine eql_v4.grouped_value(jsonb)"}, added)
	for _, object := range added {
		require.Contains(t, afterPrivileges[object], app.User+"=", object)
		require.NotContains(t, afterPrivileges[object], outsider.User+"=", object)
	}

	// The revoke from PUBLIC survives, and app's grant still lets it call.
	var got string
	require.NoError(t, connect(t, app).QueryRow(t.Context(), "SELECT eql_v4.version()").Scan(&got))
	require.Equal(t, upgradeTo, got)
	_, err = connect(t, outsider).Exec(t.Context(), "SELECT eql_v4.version()")
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	require.True(t, ok, "%v", err)
	require.Equal(t, "42501", pgErr.Code)
}

// A query locks a table and then its indexes, while the installer's DROP SCHEMA
// CASCADE locks each EQL index and then its table. The reader below holds the
// table and asks for the indexes only once the upgrade is waiting, which is
// the interleaving that deadlocks unless the upgrade locks the tables first.
func TestPostgresUpgradeWaitsForQueries(t *testing.T) {
	database := testDatabase(t)
	conn := connect(t, database)
	require.NoError(t, Install(t.Context(), conn, upgradeFrom, true))
	exec(t, conn, indexedTable)
	reader, observer := connect(t, database), connect(t, database)
	exec(t, reader, "BEGIN; LOCK TABLE encrypted IN ACCESS SHARE MODE")

	pid := conn.PgConn().PID()
	upgraded := make(chan error, 1)
	go func() {
		_, err := Upgrade(t.Context(), conn, upgradeFrom, upgradeTo, true, true)
		upgraded <- err
	}()

	require.Eventually(t, func() bool {
		var waiting bool
		err := observer.QueryRow(t.Context(), "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1 AND NOT granted)", pid).Scan(&waiting)

		return err == nil && waiting
	}, 4*time.Second, 10*time.Millisecond, "the upgrade never waited for the reader")

	// Planning locks every index on the table.
	exec(t, reader, "SELECT count(*) FROM encrypted")
	exec(t, reader, "COMMIT")
	require.NoError(t, <-upgraded)

	after, err := Inspect(t.Context(), conn)
	require.NoError(t, err)
	require.Equal(t, upgradeTo, after.Version)
}

// withRoleInstall replaces the superuser's installation with one made by a
// role that is not a superuser, then runs statements as the superuser.
func withRoleInstall(statements string) func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
	return func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
		t.Helper()

		admin := connect(t, database)
		require.NoError(t, Uninstall(t.Context(), admin))
		role := connect(t, testRole(t, database))
		// Runs before the role's cleanup, which cannot drop the role's EQL
		// objects while the superuser's objects depend on them.
		t.Cleanup(func() {
			cleanup, err := pgx.ConnectConfig(context.Background(), database)
			require.NoError(t, err)
			defer func() { _ = cleanup.Close(context.Background()) }()

			_, err = cleanup.Exec(context.Background(), "DROP SCHEMA eql_v4, eql_v4_internal CASCADE")
			require.NoError(t, err)
		})
		require.NoError(t, Install(t.Context(), role, upgradeFrom, false))
		exec(t, admin, statements)

		return role
	}
}

func TestPostgresUpgradeRefusals(t *testing.T) {
	const payloads = "CREATE TABLE payloads (id int, payload jsonb, at date);\n"
	const ordTerm = "(eql_v4.ord_term(payload::public.eql_v4_bigint_ord))"
	for _, test := range []struct {
		name     string
		setup    func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn
		from, to string
		rebuild  bool
		want     error
		named    string
	}{
		{
			name:  "index without rebuilding allowed",
			setup: withSQL(payloads + "CREATE INDEX payloads_ord ON payloads " + ordTerm),
			want:  ErrIndexesNeedRebuild,
			named: "payloads_ord",
		},
		{
			name:    "view on a view calling EQL",
			setup:   withSQL("CREATE VIEW eql_release AS SELECT eql_v4.version() AS version; CREATE VIEW release_copy AS SELECT * FROM eql_release"),
			rebuild: true,
			want:    ErrDependents,
			named:   "view release_copy",
		},
		{
			name:    "materialized view calling EQL",
			setup:   withSQL("CREATE MATERIALIZED VIEW eql_release AS SELECT eql_v4.version() AS version"),
			rebuild: true,
			want:    ErrDependents,
			named:   "materialized view eql_release",
		},
		{
			name:    "column typed with an EQL schema type",
			setup:   withSQL("CREATE TABLE terms (term eql_v4.query_text_eq)"),
			rebuild: true,
			want:    ErrDependents,
			named:   "column term of table terms",
		},
		{
			name:    "CHECK constraint calling EQL",
			setup:   withSQL("CREATE TABLE releases (id int CONSTRAINT has_eql CHECK (eql_v4.version() IS NOT NULL))"),
			rebuild: true,
			want:    ErrDependents,
			named:   "constraint has_eql on table releases",
		},
		{
			name:    "exclusion constraint calling EQL",
			setup:   withSQL(payloads + "ALTER TABLE payloads ADD CONSTRAINT one_amount EXCLUDE USING btree (" + ordTerm + " WITH =)"),
			rebuild: true,
			want:    ErrDependents,
			named:   "constraint one_amount on table payloads",
		},
		{
			name:    "policy calling EQL",
			setup:   withSQL(payloads + "CREATE POLICY has_eql ON payloads USING (eql_v4.version() IS NOT NULL)"),
			rebuild: true,
			want:    ErrDependents,
			named:   "policy has_eql on table payloads",
		},
		{
			name:    "generated column calling EQL",
			setup:   withSQL("CREATE TABLE releases (id int, version text GENERATED ALWAYS AS (eql_v4.version()) STORED)"),
			rebuild: true,
			want:    ErrDependents,
			named:   "column version of table releases",
		},
		{
			name:    "SQL function body calling EQL",
			setup:   withSQL("CREATE FUNCTION release() RETURNS text LANGUAGE sql BEGIN ATOMIC SELECT eql_v4.version(); END"),
			rebuild: true,
			want:    ErrDependents,
			named:   "function release()",
		},
		{
			name: "trigger condition calling EQL",
			setup: withSQL(payloads + `CREATE FUNCTION noop() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
CREATE TRIGGER has_eql BEFORE INSERT ON payloads FOR EACH ROW WHEN (eql_v4.version() IS NOT NULL) EXECUTE FUNCTION noop()`),
			rebuild: true,
			want:    ErrDependents,
			named:   "trigger has_eql on table payloads",
		},
		{
			name: "index on a partitioned table",
			setup: withSQL(`CREATE TABLE payloads (payload jsonb, at date) PARTITION BY RANGE (at);
CREATE TABLE payloads_2026 PARTITION OF payloads FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
CREATE INDEX payloads_ord ON payloads ` + ordTerm),
			rebuild: true,
			want:    ErrDependents,
			named:   "index payloads_ord",
		},
		{
			name: "index on a materialized view",
			setup: withSQL(payloads + `CREATE MATERIALIZED VIEW amounts AS SELECT payload FROM payloads;
CREATE INDEX amounts_ord ON amounts ` + ordTerm),
			rebuild: true,
			want:    ErrDependents,
			named:   "index amounts_ord",
		},
		{
			name:    "index with a statistics target",
			setup:   withSQL(payloads + "CREATE INDEX payloads_ord ON payloads " + ordTerm + "; ALTER INDEX payloads_ord ALTER COLUMN 1 SET STATISTICS 500"),
			rebuild: true,
			want:    ErrDependents,
			named:   "index payloads_ord",
		},
		{
			name: "index in another tablespace",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				t.Helper()

				conn := connect(t, database)
				tablespace := randomName(t, "eql_space")
				exec(t, conn, "SET allow_in_place_tablespaces = on")
				exec(t, conn, "CREATE TABLESPACE "+tablespace+" LOCATION ''")
				// Runs before the database is dropped, so the index must go first.
				t.Cleanup(func() {
					cleanup, err := pgx.ConnectConfig(context.Background(), database)
					require.NoError(t, err)
					defer func() { _ = cleanup.Close(context.Background()) }()

					_, err = cleanup.Exec(context.Background(), "DROP TABLE payloads")
					require.NoError(t, err)
					_, err = cleanup.Exec(context.Background(), "DROP TABLESPACE "+tablespace)
					require.NoError(t, err)
				})
				exec(t, conn, payloads+"CREATE INDEX payloads_ord ON payloads "+ordTerm+" TABLESPACE "+tablespace)

				return conn
			},
			rebuild: true,
			want:    ErrDependents,
			named:   "index payloads_ord",
		},
		{
			name: "index on another session's temporary table",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				t.Helper()

				exec(t, connect(t, database), "CREATE TEMPORARY TABLE payloads (payload jsonb); CREATE INDEX payloads_ord ON payloads "+ordTerm)

				return connect(t, database)
			},
			rebuild: true,
			want:    ErrDependents,
			named:   ".payloads_ord",
		},
		{
			name:    "table owned by another role",
			setup:   withRoleInstall(payloads + "CREATE INDEX payloads_ord ON payloads " + ordTerm),
			rebuild: true,
			want:    ErrNotOwner,
			named:   "table payloads",
		},
		{
			name:    "default privileges of another role",
			setup:   withRoleInstall("ALTER DEFAULT PRIVILEGES FOR ROLE " + adminConfig(t).User + " IN SCHEMA eql_v4 GRANT EXECUTE ON FUNCTIONS TO PUBLIC"),
			rebuild: true,
			want:    ErrNotOwner,
			named:   "default privileges on new functions belonging to role " + adminConfig(t).User + " in schema eql_v4",
		},
		{
			name: "role that does not own EQL",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				t.Helper()

				role := testRole(t, database)
				exec(t, connect(t, database), "GRANT USAGE ON SCHEMA eql_v4, eql_v4_internal TO "+role.User)

				return connect(t, role)
			},
			rebuild: true,
			want:    ErrNotOwner,
			named:   "schema eql_v4",
		},
		{
			// The superuser's installation has the ORE operator class. A role
			// that owns what the upgrade changes but is not a superuser
			// reinstalls without it, so the rebuilt ORE index would bind the
			// default record_ops instead.
			name: "rebuilt index with another operator class",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				t.Helper()

				admin := connect(t, database)
				role := testRole(t, database)
				// Runs before the role's cleanup, which cannot drop schemas it
				// owns while they hold the superuser's objects.
				t.Cleanup(func() {
					cleanup, err := pgx.ConnectConfig(context.Background(), database)
					require.NoError(t, err)
					defer func() { _ = cleanup.Close(context.Background()) }()

					_, err = cleanup.Exec(context.Background(), "DROP SCHEMA eql_v4, eql_v4_internal CASCADE")
					require.NoError(t, err)
				})
				exec(t, admin, fmt.Sprintf(`ALTER SCHEMA eql_v4 OWNER TO %[1]s;
ALTER SCHEMA eql_v4_internal OWNER TO %[1]s;
DO $$
DECLARE o record;
BEGIN
  FOR o IN SELECT oid::regtype::text AS name FROM pg_type WHERE typnamespace = 'public'::regnamespace AND typtype = 'd' AND typname LIKE 'eql\_v4\_%%' LOOP
    EXECUTE format('ALTER DOMAIN %%s OWNER TO %[1]s', o.name);
  END LOOP;
  FOR o IN SELECT oid::regprocedure::text AS name FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'eql\_v4\_%%' LOOP
    EXECUTE format('ALTER FUNCTION %%s OWNER TO %[1]s', o.name);
  END LOOP;
END
$$;
%[2]s
CREATE INDEX payloads_ore ON payloads (eql_v4.ord_term_ore(payload::public.eql_v4_bigint_ord_ore));
ALTER TABLE payloads OWNER TO %[1]s`, role.User, payloads))

				return connect(t, role)
			},
			rebuild: true,
			want:    ErrIndexMismatch,
			named:   "payloads_ore",
		},
		{
			name:    "downgrade",
			setup:   withSQL(""),
			from:    upgradeTo,
			to:      upgradeFrom,
			rebuild: true,
			want:    ErrDowngrade,
		},
		{
			name:    "same version",
			setup:   withSQL(""),
			to:      upgradeFrom,
			rebuild: true,
			want:    ErrDowngrade,
		},
		{
			name:    "database has another version",
			setup:   withSQL("CREATE OR REPLACE FUNCTION eql_v4.version() RETURNS text IMMUTABLE STRICT LANGUAGE sql AS $$SELECT 'go-0.0.0'$$"),
			rebuild: true,
			want:    ErrNotInstalledVersion,
		},
		{
			name: "lock held by another session",
			setup: func(t *testing.T, database *pgx.ConnConfig) *pgx.Conn {
				t.Helper()

				exec(t, connect(t, database), "SELECT pg_advisory_lock(hashtext('cipherstash.eql.lifecycle'))")

				return connect(t, database)
			},
			rebuild: true,
			want:    ErrLocked,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := testDatabase(t)
			require.NoError(t, Install(t.Context(), connect(t, database), upgradeFrom, true))
			conn := test.setup(t, database)
			from, to := upgradeFrom, upgradeTo
			if test.from != "" {
				from = test.from
			}

			if test.to != "" {
				to = test.to
			}

			before := snapshot(t, database)

			_, err := Upgrade(t.Context(), conn, from, to, false, test.rebuild)
			require.ErrorIs(t, err, test.want)
			require.True(t, Refused(err))
			if test.named != "" {
				objects, ok := errors.AsType[*ObjectsError](err)
				require.True(t, ok, "the refusal names no objects")
				// A temporary table's schema varies, so it is matched by suffix.
				require.True(t, slices.ContainsFunc(objects.Names, func(name string) bool { return strings.HasSuffix(name, test.named) }),
					"%q names none of %q", objects.Names, test.named)
			}

			require.Equal(t, before, snapshot(t, database), "a refused upgrade changed the database")
		})
	}
}

func TestPostgresUpgradeRollsBackWhenRestoreFails(t *testing.T) {
	database := testDatabase(t)
	conn := connect(t, database)
	require.NoError(t, Install(t.Context(), conn, upgradeFrom, true))
	exec(t, conn, indexedTable)
	app := testRole(t, database)
	exec(t, conn, "GRANT USAGE ON SCHEMA eql_v4, eql_v4_internal TO "+app.User)
	// The installer creates no indexes, so this fails the upgrade only once
	// it has run and the indexes are being rebuilt.
	exec(t, conn, `CREATE FUNCTION refuse_index() RETURNS event_trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''no indexes''; END';
CREATE EVENT TRIGGER refuse_index ON ddl_command_start WHEN TAG IN ('CREATE INDEX') EXECUTE FUNCTION refuse_index()`)
	before, beforeIndexes, beforePrivileges := snapshot(t, database), indexes(t, conn), privileges(t, conn)

	_, err := Upgrade(t.Context(), conn, upgradeFrom, upgradeTo, true, true)
	require.ErrorContains(t, err, "eql: restore")
	require.False(t, Refused(err))

	after, err := Inspect(t.Context(), conn)
	require.NoError(t, err)
	require.Equal(t, upgradeFrom, after.Version)
	require.Equal(t, before, snapshot(t, database), "a failed upgrade changed the database")
	require.Equal(t, beforeIndexes, indexes(t, conn))
	require.Equal(t, beforePrivileges, privileges(t, conn))
}
