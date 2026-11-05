// Package eql installs, inspects and uninstalls CipherStash EQL v4 in a
// PostgreSQL database.
//
// The installers and uninstallers are the eql-v4-install.sql and
// eql-v4-uninstall.sql assets attached to cipherstash/stack Go releases, checked
// in byte for byte under bundles/<version>/ and listed in releases.json. Each
// installer drops and re-creates the eql_v4 and eql_v4_internal schemas, so
// Install only ever runs against a database without EQL v4, and Upgrade
// captures and restores what depends on them.
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

// releases lists the entries in releases.json, oldest release first. It panics
// on a malformed manifest, which TestBundlesMatchDigests catches.
var releases = sync.OnceValue(func() []release {
	var entries []release
	if err := json.Unmarshal(manifest, &entries); err != nil {
		panic(fmt.Sprintf("eql: releases.json: %v", err))
	}

	for i, r := range entries {
		if slices.ContainsFunc(entries[:i], func(earlier release) bool { return earlier.EQLVersion == r.EQLVersion }) ||
			r.EQLVersion == "" || r.ReleaseTag == "" ||
			!sha256Hex.MatchString(r.InstallSQLSHA256) || !sha256Hex.MatchString(r.UninstallSQLSHA256) {
			panic(fmt.Sprintf("eql: releases.json: invalid or duplicate entry for %q", r.EQLVersion))
		}
	}

	return entries
})

// lookup returns the manifest entry for version and its position, or -1.
func lookup(version string) (release, int) {
	i := slices.IndexFunc(releases(), func(r release) bool { return r.EQLVersion == version })
	if i < 0 {
		return release{}, -1
	}

	return releases()[i], i
}

// Install, Upgrade and Uninstall refuse with one of these errors after rolling
// back, so the database is unchanged.
var (
	ErrUnknownVersion   = errors.New("eql: no installer is compiled in for this version")
	ErrAlreadyInstalled = errors.New("eql: the database already has an eql_v4 or eql_v4_internal schema")
	ErrLocked           = errors.New("eql: another EQL installation holds the lifecycle lock")
	ErrPgcryptoSchema   = errors.New("eql: pgcrypto is installed in a schema other than public or extensions")
	ErrPrivilege        = errors.New("eql: the role lacks CREATE on the database or on schema public")
	ErrOREUnavailable   = errors.New("eql: the installer could not create the ORE operator class")
	ErrVersionMismatch  = errors.New("eql: the installed version does not match the installer")

	// ErrDowngrade means the target version is not later than the installed one.
	ErrDowngrade = errors.New("eql: the target version is not later than the installed version")
	// ErrNotInstalledVersion means the database does not have the version an
	// upgrade starts from.
	ErrNotInstalledVersion = errors.New("eql: the database does not have the version to upgrade from")
	// ErrIndexesNeedRebuild comes wrapped in an *ObjectsError naming indexes
	// that the installer would drop and that rebuilding was not allowed for.
	ErrIndexesNeedRebuild = errors.New("eql: the installer would drop indexes")
	// ErrIndexMismatch comes wrapped in an *ObjectsError naming indexes that
	// did not come back the same after the installer ran.
	ErrIndexMismatch = errors.New("eql: rebuilt indexes differ from the originals")

	ErrNoUninstaller = errors.New("eql: no uninstaller is compiled in for the installed version")
	// ErrNotOwner, ErrInUse and ErrDependents come wrapped in an *ObjectsError
	// that names the objects involved. For ErrNotOwner they are the objects the
	// operation changes, or the tables and default privileges an upgrade
	// restores.
	ErrNotOwner = errors.New("eql: the role does not own every EQL object")
	ErrInUse    = errors.New("eql: columns use EQL domains")
	// ErrDependents means objects outside EQL depend on it; dropping the EQL
	// schemas with CASCADE, as the installer and the uninstaller do, would
	// drop them.
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

// Refused reports whether err is a check that made Install, Upgrade or
// Uninstall roll back.
func Refused(err error) bool {
	for _, refusal := range []error{
		ErrUnknownVersion, ErrAlreadyInstalled, ErrLocked, ErrPgcryptoSchema, ErrPrivilege, ErrOREUnavailable, ErrVersionMismatch,
		ErrDowngrade, ErrNotInstalledVersion, ErrIndexesNeedRebuild, ErrIndexMismatch,
		ErrNoUninstaller, ErrNotOwner, ErrInUse, ErrDependents, ErrUninstallIncomplete,
	} {
		if errors.Is(err, refusal) {
			return true
		}
	}

	return false
}

// Versions returns the versions of the compiled-in installers, oldest release
// first.
func Versions() []string {
	versions := make([]string, 0, len(releases()))
	for _, r := range releases() {
		versions = append(versions, r.EQLVersion)
	}

	return versions
}

// Later reports whether to is a compiled-in version released after from, which
// must be compiled in too. Releases are ordered by releases.json, not by name,
// which would put rc.10 before rc.2.
func Later(from, to string) bool {
	_, i := lookup(from)
	_, j := lookup(to)

	return i >= 0 && j > i
}

// SHA256 returns the SHA-256 of the compiled-in installer for version.
func SHA256(version string) (string, bool) {
	r, i := lookup(version)

	return r.InstallSQLSHA256, i >= 0
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
	_, i := lookup(version)

	return i >= 0
}

func installer(version string) (string, error) {
	r, i := lookup(version)
	if i < 0 {
		return "", ErrUnknownVersion
	}

	return bundle(version, "eql-v4-install.sql", r.InstallSQLSHA256)
}

func uninstaller(version string) (string, error) {
	r, i := lookup(version)
	if i < 0 {
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

	if err := runInstaller(ctx, tx, q, before, script, version, requireORE); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrCommitUnknown, err)
	}

	return nil
}

// runInstaller checks that the installer can run, runs it, and checks that it
// installed version, with the ORE operator class when requireORE is set.
func runInstaller(ctx context.Context, tx pgx.Tx, q *db.Queries, before Installation, script, version string, requireORE bool) error {
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

	return nil
}

// Report lists what an upgrade did that the caller should tell the user about.
type Report struct {
	// RebuiltIndexes names the indexes the upgrade dropped and re-created.
	RebuiltIndexes []string
	// RemovedObjects names the routines and types that had grants but that the
	// new release no longer has, so their grants were not restored, each as
	// "routine <signature>" or "type <name>".
	RemovedObjects []string
}

// Upgrade reinstalls EQL v4 at version to over version from in one transaction,
// restoring what the installer drops: the grants on both EQL schemas and their
// routines and types, the default privileges in them, and, when rebuildIndexes
// is set, the indexes that call EQL functions, with their comments and CLUSTER
// marks. Routines and types that are new in the release get what the restored
// default privileges grant, as if they had been created after them. Restored
// grants record the connected role as grantor. It commits only if each rebuilt
// index matches the original, the installed version matches and, when
// requireORE is set, the ORE operator class exists.
//
// It refuses, changing nothing, when to is not later than from, the database
// does not have from, another installation holds the lifecycle lock, the role
// lacks the privileges of the owner of an object the upgrade changes, any
// object outside EQL other than an index on a regular table depends on it, or
// such indexes exist and rebuildIndexes is not set. It also refuses in the
// cases Install does once EQL is absent. Those errors satisfy Refused. A
// partial installation returns ErrPartial. Every error except ErrCommitUnknown
// means the transaction rolled back; after ErrCommitUnknown, confirm the
// outcome with Inspect.
func Upgrade(ctx context.Context, conn *pgx.Conn, from, to string, requireORE, rebuildIndexes bool) (Report, error) {
	script, err := installer(to)
	if err != nil {
		return Report{}, err
	}

	if !Later(from, to) {
		return Report{}, ErrDowngrade
	}

	tx, q, err := begin(ctx, conn)
	if err != nil {
		return Report{}, err
	}

	// Rollback after Commit is a no-op; its error carries no information.
	defer func() { _ = tx.Rollback(ctx) }()

	before, err := inspect(ctx, q)
	if err != nil {
		return Report{}, err
	}

	if !before.Installed || before.Version != from {
		return Report{}, ErrNotInstalledVersion
	}

	dependents, err := q.Dependents(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("eql: list objects: %w", err)
	}

	var refused, indexes []string
	for _, d := range dependents {
		if d.RebuildableIndex == "" {
			refused = append(refused, d.Name)
		} else {
			indexes = append(indexes, d.RebuildableIndex)
		}
	}

	notOwned, err := q.ObjectsNotOwned(ctx)
	if err == nil {
		var more []string
		more, err = q.NotOwnedForUpgrade(ctx, indexes)
		notOwned = append(notOwned, more...)
	}

	if err := objects(notOwned, err, ErrNotOwner); err != nil {
		return Report{}, err
	}

	if err := objects(refused, nil, ErrDependents); err != nil {
		return Report{}, err
	}

	if !rebuildIndexes {
		if err := objects(indexes, nil, ErrIndexesNeedRebuild); err != nil {
			return Report{}, err
		}
	}

	report, err := reinstall(ctx, tx, q, before, script, to, requireORE, indexes)
	if err != nil {
		return Report{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Report{}, fmt.Errorf("%w: %w", ErrCommitUnknown, err)
	}

	return report, nil
}

// reinstall captures the grants, default privileges and indexes that running
// the installer drops, runs it, and restores them.
func reinstall(ctx context.Context, tx pgx.Tx, q *db.Queries, before Installation, script, version string, requireORE bool, indexes []string) (Report, error) {
	schemaGrants, err := q.SchemaGrants(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("eql: read schema grants: %w", err)
	}

	objectGrants, err := q.ObjectGrants(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("eql: read routine and type grants: %w", err)
	}

	defaultPrivileges, err := q.DefaultPrivileges(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("eql: read default privileges: %w", err)
	}

	existing, err := q.EQLObjects(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("eql: list routines and types: %w", err)
	}

	captured, err := q.Indexes(ctx, indexes)
	if err != nil {
		return Report{}, fmt.Errorf("eql: read indexes: %w", err)
	}

	lock, err := q.LockTables(ctx, indexes)
	if err == nil && lock != "" {
		_, err = tx.Exec(ctx, lock)
	}

	if err != nil {
		return Report{}, fmt.Errorf("eql: lock tables: %w", err)
	}

	if err := runInstaller(ctx, tx, q, before, script, version, requireORE); err != nil {
		return Report{}, err
	}

	var granted db.MissingObjectsParams
	for _, g := range objectGrants {
		if g.Kind == "routine" {
			granted.Routines = append(granted.Routines, g.Name)
		} else {
			granted.Types = append(granted.Types, g.Name)
		}
	}

	removed, err := q.MissingObjects(ctx, granted)
	if err != nil {
		return Report{}, fmt.Errorf("eql: look up routines and types: %w", err)
	}

	// The statements come from the queries in queries.sql, which quote every
	// identifier.
	restore := func(statements []string) error {
		for _, statement := range statements {
			if statement == "" {
				continue
			}

			if _, err := tx.Exec(ctx, statement); err != nil {
				return fmt.Errorf("eql: restore: %w", err)
			}
		}

		return nil
	}

	statements := slices.Concat(schemaGrants, defaultPrivileges)
	for _, g := range objectGrants {
		if !slices.Contains(removed, g.Kind+" "+g.Name) {
			statements = append(statements, g.Statement)
		}
	}

	if err := restore(statements); err != nil {
		return Report{}, err
	}

	// Routines and types that are new in the release were created before the
	// default privileges were restored, so apply those now, as PostgreSQL
	// would have when it created them.
	var old db.NewObjectGrantsParams
	for _, o := range existing {
		if o.Kind == "routine" {
			old.Routines = append(old.Routines, o.Name)
		} else {
			old.Types = append(old.Types, o.Name)
		}
	}

	defaults, err := q.NewObjectGrants(ctx, old)
	if err != nil {
		return Report{}, fmt.Errorf("eql: read default privileges for new objects: %w", err)
	}

	statements = defaults
	var analyze []string
	for _, index := range captured {
		statements = append(statements, index.Definition, index.Comment, index.Cluster)
		analyze = append(analyze, index.AnalyzeTable)
	}

	slices.Sort(analyze)
	// Expression indexes keep their own statistics, which went with the
	// dropped indexes.
	if err := restore(append(statements, slices.Compact(analyze)...)); err != nil {
		return Report{}, err
	}

	rebuilt, err := q.Indexes(ctx, indexes)
	if err != nil {
		return Report{}, fmt.Errorf("eql: read rebuilt indexes: %w", err)
	}

	var differ []string
	for _, index := range captured {
		if !slices.Contains(rebuilt, index) {
			differ = append(differ, index.Name)
		}
	}

	if err := objects(differ, nil, ErrIndexMismatch); err != nil {
		return Report{}, err
	}

	return Report{RebuiltIndexes: indexes, RemovedObjects: removed}, nil
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
		{func(ctx context.Context) ([]string, error) {
			dependents, err := q.Dependents(ctx)
			names := make([]string, len(dependents))
			for i, d := range dependents {
				names[i] = d.Name
			}

			return names, err
		}, ErrDependents},
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
