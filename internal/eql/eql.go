// Package eql installs, inspects and uninstalls CipherStash EQL v4 in a
// PostgreSQL database.
//
// The installers and uninstallers are the eql-v4-install.sql and
// eql-v4-uninstall.sql assets attached to cipherstash/stack Go releases, checked
// in byte for byte under bundles/<version>/ and listed in releases.json. Each
// installer drops and re-creates the eql_v4 and eql_v4_internal schemas, so
// Install only ever runs against a database without EQL v4.
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
	"strings"
	"sync"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/eql/internal/db"
	"github.com/jackc/pgx/v5"
)

const (
	// Schema and InternalSchema are the schemas every EQL v4 installer creates.
	Schema         = "eql_v4"
	InternalSchema = "eql_v4_internal"
)

//go:embed bundles/*/eql-v4-install.sql bundles/*/eql-v4-uninstall.sql
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
	// UninstallSQLSHA256 is the hex SHA-256 of the eql-v4-uninstall.sql asset.
	UninstallSQLSHA256 string `json:"uninstallSqlSha256"`
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// releases maps each version in releases.json to its entry. It panics on a
// malformed manifest, which TestBundlesMatchDigests catches.
var releases = sync.OnceValue(func() map[string]release {
	var entries []release
	if err := json.Unmarshal(manifest, &entries); err != nil {
		panic(fmt.Sprintf("eql: releases.json: %v", err))
	}

	byVersion := make(map[string]release, len(entries))
	for _, r := range entries {
		if _, duplicate := byVersion[r.EQLVersion]; duplicate || r.EQLVersion == "" || r.ReleaseTag == "" ||
			!sha256Hex.MatchString(r.InstallSQLSHA256) || !sha256Hex.MatchString(r.UninstallSQLSHA256) {
			panic(fmt.Sprintf("eql: releases.json: invalid or duplicate entry for %q", r.EQLVersion))
		}

		byVersion[r.EQLVersion] = r
	}

	return byVersion
})

// Install and Uninstall refuse with one of these errors after rolling back, so
// the database is unchanged.
var (
	ErrUnknownVersion   = errors.New("eql: no installer is compiled in for this version")
	ErrAlreadyInstalled = errors.New("eql: the database already has an eql_v4 or eql_v4_internal schema")
	ErrLocked           = errors.New("eql: another EQL installation holds the lifecycle lock")
	ErrPgcryptoSchema   = errors.New("eql: pgcrypto is installed in a schema other than public or extensions")
	ErrPrivilege        = errors.New("eql: the role lacks CREATE on the database or on schema public")
	ErrOREUnavailable   = errors.New("eql: the installer could not create the ORE operator class")
	ErrVersionMismatch  = errors.New("eql: the installed version does not match the installer")

	ErrNoUninstaller = errors.New("eql: no uninstaller is compiled in for the installed version")
	// ErrNotOwner, ErrInUse and ErrDependents come wrapped in an *ObjectsError
	// that names the objects involved.
	ErrNotOwner = errors.New("eql: the role does not own every EQL object")
	ErrInUse    = errors.New("eql: columns use EQL domains")
	// ErrDependents means objects outside EQL depend on it; the uninstaller's
	// CASCADE would drop them.
	ErrDependents = errors.New("eql: objects outside EQL depend on it")
	// ErrUninstallIncomplete means EQL objects remained after the uninstaller ran.
	ErrUninstallIncomplete = errors.New("eql: EQL objects remain after uninstalling")
)

// maxNamedObjects caps how many objects an ObjectsError names.
const maxNamedObjects = 20

// ObjectsError is a refusal that names the database objects behind it, as
// PostgreSQL describes them. Names are identifiers, never row values. At most
// maxNamedObjects are named; Total counts them all.
type ObjectsError struct {
	Err   error
	Names []string
	Total int
}

func (e *ObjectsError) Error() string {
	return fmt.Sprintf("%v: %s", e.Err, strings.Join(e.Names, ", "))
}

func (e *ObjectsError) Unwrap() error { return e.Err }

var (
	// ErrPartial means only some of the EQL v4 objects Inspect expects are present.
	ErrPartial = errors.New("eql: the database has an incomplete EQL v4 installation")
	// ErrCommitUnknown means COMMIT failed without a reply, so the installation
	// may or may not have committed.
	ErrCommitUnknown = errors.New("eql: the outcome of COMMIT is unknown")
)

// Refused reports whether err is a check that made Install or Uninstall roll back.
func Refused(err error) bool {
	for _, refusal := range []error{
		ErrUnknownVersion, ErrAlreadyInstalled, ErrLocked, ErrPgcryptoSchema, ErrPrivilege, ErrOREUnavailable, ErrVersionMismatch,
		ErrNoUninstaller, ErrNotOwner, ErrInUse, ErrDependents, ErrUninstallIncomplete,
	} {
		if errors.Is(err, refusal) {
			return true
		}
	}

	return false
}

// Versions returns the versions of the compiled-in installers, sorted.
func Versions() []string {
	versions := make([]string, 0, len(releases()))
	for version := range releases() {
		versions = append(versions, version)
	}

	slices.Sort(versions)

	return versions
}

// SHA256 returns the SHA-256 of the compiled-in installer for version.
func SHA256(version string) (string, bool) {
	r, ok := releases()[version]

	return r.InstallSQLSHA256, ok
}

// bundle reads a compiled-in script and checks it against its digest.
func bundle(version, name, digest string) (string, error) {
	script, err := bundles.ReadFile("bundles/" + version + "/" + name)
	if err != nil {
		return "", fmt.Errorf("eql: read %s: %w", name, err)
	}

	sum := sha256.Sum256(script)
	if hex.EncodeToString(sum[:]) != digest {
		return "", fmt.Errorf("eql: %s for %s does not match its digest", name, version)
	}

	return string(script), nil
}

// Uninstallable reports whether an uninstaller is compiled in for version.
func Uninstallable(version string) bool {
	_, ok := releases()[version]

	return ok
}

func installer(version string) (string, error) {
	r, ok := releases()[version]
	if !ok {
		return "", ErrUnknownVersion
	}

	return bundle(version, "eql-v4-install.sql", r.InstallSQLSHA256)
}

func uninstaller(version string) (string, error) {
	r, ok := releases()[version]
	if !ok {
		return "", ErrNoUninstaller
	}

	return bundle(version, "eql-v4-uninstall.sql", r.UninstallSQLSHA256)
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

// begin starts a transaction that holds the lifecycle lock, and configures it
// for running an installer or uninstaller. On error the transaction is rolled back.
func begin(ctx context.Context, conn *pgx.Conn) (pgx.Tx, *db.Queries, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("eql: begin: %w", err)
	}

	q := db.New(tx)
	locked, err := q.TryLifecycleLock(ctx)
	switch {
	case err != nil:
		err = fmt.Errorf("eql: lock: %w", err)
	case !locked:
		err = ErrLocked
	default:
		if err = q.ConfigureTransaction(ctx); err != nil {
			err = fmt.Errorf("eql: configure transaction: %w", err)
		}
	}

	if err != nil {
		_ = tx.Rollback(ctx)

		return nil, nil, err
	}

	return tx, q, nil
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

	tx, q, err := begin(ctx, conn)
	if err != nil {
		return err
	}

	// Rollback after Commit is a no-op; its error carries no information.
	defer func() { _ = tx.Rollback(ctx) }()

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

// objects returns an *ObjectsError wrapping refusal when a query named any
// objects.
func objects(names []string, err, refusal error) error {
	if err != nil {
		return fmt.Errorf("eql: list objects: %w", err)
	}

	if len(names) == 0 {
		return nil
	}

	return &ObjectsError{Err: refusal, Names: names[:min(len(names), maxNamedObjects)], Total: len(names)}
}

// Uninstall removes EQL v4 from the connected database in one transaction. It
// runs the compiled-in uninstaller for the installed version, which drops both
// EQL schemas with CASCADE, then drops the domains and functions it leaves in
// schema public without CASCADE, and commits only when no EQL object remains.
// It succeeds without changes when EQL is not installed.
//
// It refuses, changing nothing, when another installation holds the lifecycle
// lock, no uninstaller is compiled in for the installed version, the role
// lacks the privileges of the owner of an object it drops by name, any column
// uses an EQL domain, or any object outside EQL depends on it. Those errors
// satisfy Refused. A partial installation returns ErrPartial. Every error
// except ErrCommitUnknown means the transaction rolled back; after
// ErrCommitUnknown, confirm the outcome with Inspect.
func Uninstall(ctx context.Context, conn *pgx.Conn) error {
	tx, q, err := begin(ctx, conn)
	if err != nil {
		return err
	}

	// Rollback after Commit is a no-op; its error carries no information.
	defer func() { _ = tx.Rollback(ctx) }()

	inst, err := inspect(ctx, q)
	if err != nil {
		return err
	}

	if !inst.Installed {
		return nil
	}

	// The database, not state, says which release is installed: it can have
	// been reinstalled outside Terraform.
	script, err := uninstaller(inst.Version)
	if err != nil {
		return err
	}

	for _, check := range []struct {
		list    func(context.Context) ([]string, error)
		refusal error
	}{
		{q.ObjectsNotOwned, ErrNotOwner},
		{q.ColumnsUsingDomains, ErrInUse},
		{q.Dependents, ErrDependents},
	} {
		names, err := check.list(ctx)
		if err := objects(names, err, check.refusal); err != nil {
			return err
		}
	}

	if _, err := tx.Conn().PgConn().Exec(ctx, script).ReadAll(); err != nil {
		return fmt.Errorf("eql: run uninstaller: %w", err)
	}

	if err := q.DropLeftovers(ctx); err != nil {
		return fmt.Errorf("eql: drop leftovers: %w", err)
	}

	remaining, err := q.AnyEQLObjectRemains(ctx)
	if err != nil {
		return fmt.Errorf("eql: check uninstall: %w", err)
	}

	if remaining {
		return ErrUninstallIncomplete
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrCommitUnknown, err)
	}

	return nil
}
