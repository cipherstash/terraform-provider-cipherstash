// Package eql installs and inspects CipherStash EQL v4 in a PostgreSQL database.
//
// The installers are the eql-v4-install.sql assets attached to cipherstash/stack
// Go releases, checked in byte for byte under bundles/<version>/ and listed in
// releases.json. Each installer drops and re-creates the eql_v4 and eql_v4_internal
// schemas, so Install only ever runs against a database without EQL v4.
//
// Every other statement is in queries.sql, from which sqlc generates internal/db.
package eql

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sync"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/eql/internal/db"
	"github.com/jackc/pgx/v5"
)

const (
	// Schema and InternalSchema are the schemas every EQL v4 installer creates.
	Schema         = "eql_v4"
	InternalSchema = "eql_v4_internal"
)

//go:embed bundles/*/eql-v4-install.sql
var bundles embed.FS

// releases.json lists each compiled-in installer. It is JSON so that release
// tooling can generate it, and its field names follow the release-manifest.json
// that cipherstash/stack publishes for EQL v3.
//
//go:embed releases.json
var manifest []byte

type release struct {
	// EQLVersion is what eql_v4.version() returns once the installer has run.
	EQLVersion string `json:"eqlVersion"`
	// ReleaseTag is the cipherstash/stack release the installer is attached to.
	ReleaseTag string `json:"releaseTag"`
	// InstallSQLSHA256 is the hex SHA-256 of the eql-v4-install.sql asset.
	InstallSQLSHA256 string `json:"installSqlSha256"`
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// digests maps each version in releases.json to its installer's SHA-256. It
// panics on a malformed manifest, which TestBundlesMatchDigests catches.
var digests = sync.OnceValue(func() map[string]string {
	var releases []release
	if err := json.Unmarshal(manifest, &releases); err != nil {
		panic(fmt.Sprintf("eql: releases.json: %v", err))
	}

	byVersion := make(map[string]string, len(releases))
	for _, r := range releases {
		if _, duplicate := byVersion[r.EQLVersion]; duplicate || r.EQLVersion == "" || r.ReleaseTag == "" || !sha256Hex.MatchString(r.InstallSQLSHA256) {
			panic(fmt.Sprintf("eql: releases.json: invalid or duplicate entry for %q", r.EQLVersion))
		}

		byVersion[r.EQLVersion] = r.InstallSQLSHA256
	}

	return byVersion
})

// Install refuses with one of these errors after rolling back, so the
// database is unchanged.
var (
	ErrUnknownVersion   = errors.New("eql: no installer is compiled in for this version")
	ErrAlreadyInstalled = errors.New("eql: the database already has an eql_v4 or eql_v4_internal schema")
	ErrLocked           = errors.New("eql: another EQL installation holds the lifecycle lock")
	ErrPgcryptoSchema   = errors.New("eql: pgcrypto is installed in a schema other than public or extensions")
	ErrPrivilege        = errors.New("eql: the role lacks CREATE on the database or on schema public")
	ErrOREUnavailable   = errors.New("eql: the installer could not create the ORE operator class")
	ErrVersionMismatch  = errors.New("eql: the installed version does not match the installer")
)

var (
	// ErrPartial means only some of the EQL v4 objects Inspect expects are present.
	ErrPartial = errors.New("eql: the database has an incomplete EQL v4 installation")
	// ErrCommitUnknown means COMMIT failed without a reply, so the installation
	// may or may not have committed.
	ErrCommitUnknown = errors.New("eql: the outcome of COMMIT is unknown")
)

// Refused reports whether err is a check that made Install roll back.
func Refused(err error) bool {
	for _, refusal := range []error{ErrUnknownVersion, ErrAlreadyInstalled, ErrLocked, ErrPgcryptoSchema, ErrPrivilege, ErrOREUnavailable, ErrVersionMismatch} {
		if errors.Is(err, refusal) {
			return true
		}
	}

	return false
}

// Versions returns the versions of the compiled-in installers, sorted.
func Versions() []string {
	versions := make([]string, 0, len(digests()))
	for version := range digests() {
		versions = append(versions, version)
	}

	slices.Sort(versions)

	return versions
}

// SHA256 returns the SHA-256 of the compiled-in installer for version.
func SHA256(version string) (string, bool) {
	digest, ok := digests()[version]

	return digest, ok
}

func installer(version string) (string, error) {
	digest, ok := digests()[version]
	if !ok {
		return "", ErrUnknownVersion
	}

	script, err := bundles.ReadFile("bundles/" + version + "/eql-v4-install.sql")
	if err != nil {
		return "", fmt.Errorf("eql: read installer: %w", err)
	}

	sum := sha256.Sum256(script)
	if hex.EncodeToString(sum[:]) != digest {
		return "", fmt.Errorf("eql: installer for %s does not match its digest", version)
	}

	return string(script), nil
}

// Installation describes what Inspect found.
type Installation struct {
	// Installed is false when neither EQL v4 schema exists. The other fields
	// except PgcryptoSchema are then empty.
	Installed bool
	// Version is what eql_v4.version() returns.
	Version string
	// Owner is the role that owns schema eql_v4: the role that ran the installer.
	Owner string
	// OREAvailable is true when the ORE operator class exists and no domain
	// carries the eql_ore_unavailable constraint the installer adds without it.
	OREAvailable bool
	// PgcryptoSchema is the schema of the pgcrypto extension, or empty when
	// pgcrypto is not installed.
	PgcryptoSchema string
}

// Inspect reads the EQL v4 installation in the connected database. It only reads.
func Inspect(ctx context.Context, conn *pgx.Conn) (Installation, error) {
	return inspect(ctx, db.New(conn))
}

func inspect(ctx context.Context, q *db.Queries) (Installation, error) {
	schemas, err := q.InspectSchemas(ctx)
	if err != nil {
		return Installation{}, fmt.Errorf("eql: inspect schemas: %w", err)
	}

	inst := Installation{PgcryptoSchema: schemas.PgcryptoSchema}
	if !schemas.HasSchema && !schemas.HasInternalSchema {
		return inst, nil
	}

	if !schemas.HasSchema || !schemas.HasInternalSchema || !schemas.HasVersion {
		return inst, ErrPartial
	}

	installation, err := q.InspectInstallation(ctx)
	if err != nil {
		return Installation{}, fmt.Errorf("eql: inspect installation: %w", err)
	}

	inst.Installed, inst.Owner = true, schemas.Owner
	inst.Version, inst.OREAvailable = installation.Version, installation.OreAvailable

	return inst, nil
}

// Install installs EQL v4 at version into the connected database in one
// transaction, and commits only if the installed version matches and, when
// requireORE is set, the ORE operator class was created.
//
// It refuses, changing nothing, when the database already has either EQL v4
// schema, another installation holds the lifecycle lock, pgcrypto is in an
// unsupported schema or the role lacks CREATE on the database or on public.
// Those errors satisfy Refused. Every error except ErrCommitUnknown means the
// transaction rolled back; after ErrCommitUnknown, confirm the outcome with Inspect.
func Install(ctx context.Context, conn *pgx.Conn, version string, requireORE bool) error {
	script, err := installer(version)
	if err != nil {
		return err
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("eql: begin: %w", err)
	}

	// Rollback after Commit is a no-op; its error carries no information.
	defer func() { _ = tx.Rollback(ctx) }()

	q := db.New(tx)
	locked, err := q.TryLifecycleLock(ctx)
	if err != nil {
		return fmt.Errorf("eql: lock: %w", err)
	}

	if !locked {
		return ErrLocked
	}

	if err := q.ConfigureTransaction(ctx); err != nil {
		return fmt.Errorf("eql: configure transaction: %w", err)
	}

	before, err := inspect(ctx, q)
	if errors.Is(err, ErrPartial) || err == nil && before.Installed {
		// The installer starts by dropping both schemas with CASCADE, which
		// would remove every grant and index that depends on them.
		return ErrAlreadyInstalled
	}

	if err != nil {
		return err
	}

	// The installer creates pgcrypto in schema extensions when it is absent,
	// accepts public, and fails anywhere else.
	if before.PgcryptoSchema != "" && before.PgcryptoSchema != "public" && before.PgcryptoSchema != "extensions" {
		return ErrPgcryptoSchema
	}

	canCreate, err := q.CanCreate(ctx)
	if err != nil {
		return fmt.Errorf("eql: check privileges: %w", err)
	}

	if !canCreate {
		return ErrPrivilege
	}

	// The installer is many statements, so it runs through the simple query
	// protocol. It has no transaction control of its own.
	if _, err := tx.Conn().PgConn().Exec(ctx, script).ReadAll(); err != nil {
		return fmt.Errorf("eql: run installer: %w", err)
	}

	after, err := inspect(ctx, q)
	if err != nil {
		return err
	}

	comment, err := q.SchemaComment(ctx)
	if err != nil {
		return fmt.Errorf("eql: read schema comment: %w", err)
	}

	if !after.Installed || after.Version != version || comment != version {
		return ErrVersionMismatch
	}

	// Without the operator class the installer disables the ORE domains and
	// still succeeds.
	if requireORE && !after.OREAvailable {
		return ErrOREUnavailable
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrCommitUnknown, err)
	}

	return nil
}
