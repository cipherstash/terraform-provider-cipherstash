package eql

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestBundlesMatchDigests(t *testing.T) {
	dirs, err := fs.ReadDir(bundles, "bundles")
	require.NoError(t, err)

	embedded := map[string]bool{}
	for _, dir := range dirs {
		script, err := bundles.ReadFile(path.Join("bundles", dir.Name(), "eql-v4-install.sql"))
		require.NoError(t, err)

		sum := sha256.Sum256(script)
		digest, ok := SHA256(dir.Name())
		require.True(t, ok, "bundles/%s has no digest", dir.Name())
		require.Equal(t, digest, hex.EncodeToString(sum[:]), "bundles/%s does not match its digest", dir.Name())

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

// snapshot lists the database's schemas, extensions and functions.
func snapshot(t *testing.T, database *pgx.ConnConfig) []string {
	t.Helper()

	rows, err := connect(t, database).Query(t.Context(), `
SELECT 'schema ' || nspname FROM pg_namespace
UNION ALL SELECT 'extension ' || extname FROM pg_extension
UNION ALL SELECT 'function ' || p.oid::regprocedure::text FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY 1`)
	require.NoError(t, err)

	objects, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)

	return objects
}
