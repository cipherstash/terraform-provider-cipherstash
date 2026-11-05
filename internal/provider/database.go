package provider

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/eql"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const defaultConnectTimeout = 15 * time.Second

var errDatabaseSettingsUnknown = errors.New("provider database settings are unknown")

// postgresDatabase opens one connection per operation from the provider's
// database settings, falling back to the libpq environment for unset values.
type postgresDatabase struct {
	settings databaseModel
	// unknown is set when the whole database object was unknown at Configure.
	unknown bool
}

func (d postgresDatabase) InspectEQL(ctx context.Context, database string) (eql.Installation, error) {
	conn, err := d.connect(ctx, database)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "3D000" {
		// The server reports that the database does not exist, so neither does EQL.
		return eql.Installation{}, nil
	}

	if err != nil {
		return eql.Installation{}, err
	}

	defer closeConn(ctx, conn)

	return eql.Inspect(ctx, conn)
}

func (d postgresDatabase) InstallEQL(ctx context.Context, database, version string, requireORE bool) error {
	conn, err := d.connect(ctx, database)
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)

	return eql.Install(ctx, conn, version, requireORE)
}

func (d postgresDatabase) UninstallEQL(ctx context.Context, database string) error {
	conn, err := d.connect(ctx, database)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "3D000" {
		// The database is gone, and EQL with it.
		return nil
	}

	if err != nil {
		return err
	}

	defer closeConn(ctx, conn)

	return eql.Uninstall(ctx, conn)
}

func closeConn(ctx context.Context, conn *pgx.Conn) {
	if err := conn.Close(ctx); err != nil {
		tflog.Debug(ctx, "Closing the PostgreSQL connection failed")
	}
}

func (d postgresDatabase) connect(ctx context.Context, database string) (*pgx.Conn, error) {
	s := d.settings
	if d.unknown || s.Host.IsUnknown() || s.Port.IsUnknown() || s.Username.IsUnknown() || s.Password.IsUnknown() || s.SSLMode.IsUnknown() || s.SSLRootCert.IsUnknown() {
		return nil, errDatabaseSettingsUnknown
	}

	// Keywords left out of the connection string take libpq's environment
	// defaults, which pgx applies while parsing.
	keywords := map[string]string{"dbname": database}
	set := func(keyword string, null bool, value string) {
		if !null {
			keywords[keyword] = value
		}
	}
	set("host", s.Host.IsNull(), s.Host.ValueString())
	set("port", s.Port.IsNull(), strconv.FormatInt(s.Port.ValueInt64(), 10))
	set("user", s.Username.IsNull(), s.Username.ValueString())
	set("password", s.Password.IsNull(), s.Password.ValueString())
	set("sslmode", s.SSLMode.IsNull(), s.SSLMode.ValueString())
	set("sslrootcert", s.SSLRootCert.IsNull(), s.SSLRootCert.ValueString())

	var dsn strings.Builder
	for keyword, value := range keywords {
		dsn.WriteString(keyword + "='" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(value) + "' ")
	}

	config, err := pgx.ParseConfig(dsn.String())
	if err != nil {
		return nil, err
	}

	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = defaultConnectTimeout
	}

	config.OnNotice = func(_ *pgconn.PgConn, notice *pgconn.Notice) {
		tflog.Debug(ctx, "PostgreSQL notice", map[string]any{"severity": notice.Severity, "message": notice.Message})
	}

	return pgx.ConnectConfig(ctx, config)
}

// databaseError describes a database failure without PostgreSQL's message or
// detail, which can quote submitted values.
func databaseError(err error) string {
	pgErr, _ := errors.AsType[*pgconn.PgError](err)
	netErr, _ := errors.AsType[net.Error](err)
	code := ""
	if pgErr != nil {
		code = pgErr.Code
	}

	switch {
	case errors.Is(err, errDatabaseSettingsUnknown):
		return "The provider's database settings are not known yet, for example because they depend on a resource Terraform has not created. Apply the resources they depend on first."
	case errors.Is(err, eql.ErrPartial):
		return "The database has the eql_v4 or eql_v4_internal schema but not a complete EQL v4 installation. Inspect it by hand; this provider will not repair or replace it."
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "The database operation was cancelled or timed out."
	case strings.HasPrefix(code, "28"):
		return "PostgreSQL rejected the credentials. Check the provider's database username and password."
	case code == "3D000":
		return "The database does not exist on the configured PostgreSQL server."
	case code == "2BP01":
		return "Other database objects still depend on an object the operation drops, so it rolled back. Remove them and retry."
	case code == "53200":
		return "PostgreSQL ran out of shared memory, usually because the operation needs more locks than the lock table has free. Retry when the server is quiet, or raise max_locks_per_transaction, which needs a server restart."
	case code == "42501":
		return "The database role lacks a privilege the operation needs."
	case code == "55P03":
		return "A database lock was not available before the lock timeout. Another session may be using the objects involved; retry when it has finished."
	case code == "57014":
		return "PostgreSQL cancelled the statement, usually because it exceeded the statement timeout."
	case strings.HasPrefix(code, "08"), netErr != nil:
		return "Could not connect to PostgreSQL. Check the provider's database host, port and TLS settings."
	case code != "":
		return "PostgreSQL returned error code " + code + ". Check the server log for details."
	default:
		return "The database operation failed. Check the provider's database settings and the server log."
	}
}
