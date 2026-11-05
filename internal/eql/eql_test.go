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
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestBundlesMatchDigests(t *testing.T) {
	dirs, err := fs.ReadDir(bundles, "bundles")
	require.NoError(t, err)

	embedded := map[string]bool{}
	for _, dir := range dirs {
		r, ok := releases()[dir.Name()]
		require.True(t, ok, "bundles/%s has no manifest entry", dir.Name())

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

const version = "go-0.1.0-rc.3"

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
