// Package provider manages CipherStash actors, clients, keysets and grants through native Go clients,
// and installs EQL v4 into PostgreSQL databases.
package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/eql"
	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/auth"
	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/manage"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/sethvargo/go-envconfig"
)

type Provider struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

func New() *Provider { return &Provider{} }

type providerModel struct {
	Auth     types.Object `tfsdk:"auth"`
	Database types.Object `tfsdk:"database"`
}

type authModel struct {
	WorkspaceCRN    types.String `tfsdk:"workspace_crn"`
	ClientAccessKey types.String `tfsdk:"client_access_key"`
}

type databaseModel struct {
	Host        types.String `tfsdk:"host"`
	Port        types.Int64  `tfsdk:"port"`
	Username    types.String `tfsdk:"username"`
	Password    types.String `tfsdk:"password"`
	SSLMode     types.String `tfsdk:"sslmode"`
	SSLRootCert types.String `tfsdk:"sslrootcert"`
}

var (
	authAttributeTypes = map[string]attr.Type{
		"workspace_crn":     types.StringType,
		"client_access_key": types.StringType,
	}
	databaseAttributeTypes = map[string]attr.Type{
		"host":        types.StringType,
		"port":        types.Int64Type,
		"username":    types.StringType,
		"password":    types.StringType,
		"sslmode":     types.StringType,
		"sslrootcert": types.StringType,
	}
)

// providerData is what resources and data sources receive. Each half is nil
// when its provider setting is absent.
type providerData struct {
	manage   manageClient
	database eqlDatabase
}

func (p *Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "cipherstash"
}

func (p *Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use the CipherStash provider to manage machine identities, ZeroKMS clients, keysets, and keyset grants in a workspace, and to install EQL v4 into PostgreSQL databases. Configure a separate provider instance for each workspace. See the [workspace documentation](https://cipherstash.com/docs/reference/workspace) for the CipherStash concepts.\n\nThe provider has two optional halves. `auth` connects to a CipherStash workspace and is required by every CipherStash resource and data source. `database` connects to a PostgreSQL server and is required by `cipherstash_eql_v4`. Without `auth`, the provider never reads `CS_*` environment variables or contacts CipherStash; without `database`, it never connects to PostgreSQL.\n\nThis provider is in development and is not published to the Terraform Registry. It uses this repository's public pkg/stack/auth and pkg/stack/manage Go packages. Builds require no BNDRY module, sibling SDK checkout, local module replacement or WebAssembly guest. The provider is licensed under the MIT License.\n\nAuthenticate with an Admin access key. The provider requires a verified Admin role even for configurations that manage only ZeroKMS resources or read data sources. Successful configuration does not prove permission for every operation. Create this credential outside the Terraform configuration that uses it. Resource access keys and client key values are stored in Terraform state and saved plans, even when marked sensitive. Provider settings are not stored in state, but saved plans can contain them. Protect these files and your state backend.\n\nNeither the provider nor manage.Config reads CS_CLIENT_ID: it identifies an application encryption client, not an authentication principal. Manage client/keyset pairs explicitly with cipherstash_zerokms_keyset_grant.",
		Attributes: map[string]schema.Attribute{
			"auth": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Connection to a CipherStash workspace. Every CipherStash resource and data source requires it. Set it to `{}` to take both values from the environment. When it is omitted, the provider never reads `CS_WORKSPACE_CRN`, `CS_CLIENT_ACCESS_KEY` or `CS_CTS_HOST` and never contacts CipherStash. When `CS_CTS_HOST` is set, as in CipherStash's SDKs, the provider sends the access key and management requests to that CipherStash Token Service instead of the workspace region's, and requires it to have issued the tokens. It must be an HTTPS URL, or HTTP to a loopback host, without credentials, query or fragment; an empty value is ignored.",
				Attributes: map[string]schema.Attribute{
					"workspace_crn":     schema.StringAttribute{Optional: true, Description: "CipherStash Resource Name (CRN) of the workspace, in the format `crn:<region>.aws:<workspace ID>`. Omit this argument or set it to null to use `CS_WORKSPACE_CRN`. Explicit known values override the environment. Empty, unknown or malformed selected values are rejected without fallback; no saved profile is read."},
					"client_access_key": schema.StringAttribute{Optional: true, Sensitive: true, Description: "Access key with the Admin role for this workspace. Omit this argument or set it to null to use `CS_CLIENT_ACCESS_KEY`. Explicit known values override the environment. Empty, unknown or malformed selected values are rejected without fallback. `CS_ACCESS_KEY`, `CS_CONTROL_ACCESS_KEY` and `CIPHERSTASH_ACCESS_KEY` are ignored. Native authentication verifies the token's signature, issuer, audience, expiry, workspace and Admin role before using it. Credentials without Admin, including Control-only and Member-only credentials, are rejected. CipherStash services authorize each request."},
				},
			},
			"database": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Connection to a PostgreSQL server. `cipherstash_eql_v4` requires it and names the database to use. Unset arguments fall back to the libpq environment variables `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGSSLMODE` and `PGSSLROOTCERT`, and to the password file. Connect as a role that can create the ORE operator class: a superuser, or `rds_superuser` on Amazon RDS and Aurora. The connection opens only when a resource needs it, so these values may be unknown during planning.",
				Attributes: map[string]schema.Attribute{
					"host":        schema.StringAttribute{Optional: true, Description: "Server host name or IP address. Null uses `PGHOST`."},
					"port":        schema.Int64Attribute{Optional: true, Description: "Server port. Null uses `PGPORT`, or 5432.", Validators: []validator.Int64{int64validator.Between(1, 65535)}},
					"username":    schema.StringAttribute{Optional: true, Description: "Role to connect as. Null uses `PGUSER`. The role that installs EQL owns every EQL object."},
					"password":    schema.StringAttribute{Optional: true, Sensitive: true, Description: "Password for the role. Null uses `PGPASSWORD` or the password file."},
					"sslmode":     schema.StringAttribute{Optional: true, Description: "libpq TLS mode: `disable`, `allow`, `prefer`, `require`, `verify-ca` or `verify-full`. Null uses `PGSSLMODE`, or `prefer`. Use `verify-full` outside local development.", Validators: []validator.String{stringvalidator.OneOf("disable", "allow", "prefer", "require", "verify-ca", "verify-full")}},
					"sslrootcert": schema.StringAttribute{Optional: true, Description: "Path to the certificate authorities that verify the server certificate. Null uses `PGSSLROOTCERT`."},
				},
			},
		},
	}
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.close()

	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	data := &providerData{}
	switch {
	case cfg.Auth.IsUnknown():
		resp.Diagnostics.AddAttributeError(path.Root("auth"), "Unknown auth settings", "The auth settings must be known before configuring this provider.")
	case !cfg.Auth.IsNull():
		var settings authModel
		resp.Diagnostics.Append(cfg.Auth.As(ctx, &settings, basetypes.ObjectAsOptions{})...)
		if !resp.Diagnostics.HasError() {
			data.manage = p.configureAuth(ctx, settings, &resp.Diagnostics)
		}
	}

	if !cfg.Database.IsNull() {
		database := postgresDatabase{unknown: cfg.Database.IsUnknown()}
		if !database.unknown {
			resp.Diagnostics.Append(cfg.Database.As(ctx, &database.settings, basetypes.ObjectAsOptions{})...)
		}

		data.database = database
	}

	if resp.Diagnostics.HasError() {
		return
	}

	resp.ResourceData = data
	resp.DataSourceData = data
}

// configureAuth must be called with p.mu held.
func (p *Provider) configureAuth(ctx context.Context, cfg authModel, diags *diag.Diagnostics) manageClient {
	crnPath, keyPath := path.Root("auth").AtName("workspace_crn"), path.Root("auth").AtName("client_access_key")

	crnText := cfg.WorkspaceCRN.ValueString()
	if cfg.WorkspaceCRN.IsNull() {
		crnText = os.Getenv("CS_WORKSPACE_CRN")
	}

	if cfg.WorkspaceCRN.IsUnknown() || crnText == "" {
		diags.AddAttributeError(crnPath, "Workspace CRN required", "Set auth.workspace_crn or CS_WORKSPACE_CRN to a known workspace CRN. Explicit empty or unknown values do not use the environment fallback.")
	}

	keyText := cfg.ClientAccessKey.ValueString()
	if cfg.ClientAccessKey.IsUnknown() {
		diags.AddAttributeError(keyPath, "Unknown access key", "The access key must be known before configuring this provider. Unknown values do not use the environment fallback.")
	} else {
		if cfg.ClientAccessKey.IsNull() {
			keyText = os.Getenv("CS_CLIENT_ACCESS_KEY")
		}

		if keyText == "" {
			diags.AddAttributeError(keyPath, "Client access key required", "Set auth.client_access_key or CS_CLIENT_ACCESS_KEY to an Admin key. Bootstrap this credential outside this Terraform root.")
		}
	}

	if diags.HasError() {
		return nil
	}

	// Decode only the selected values, never falling back to the environment again.
	var clientConfig manage.Config[auth.AdminAccessKey]
	if err := envconfig.ProcessWith(ctx, &envconfig.Config{
		Target: &clientConfig,
		Lookuper: envconfig.MapLookuper(map[string]string{
			"CS_WORKSPACE_CRN":     crnText,
			"CS_CLIENT_ACCESS_KEY": keyText,
		}),
	}); err != nil {
		// Config decodes the CRN before the key and stops at the first error.
		// Keep diagnostics attribute-specific without exposing decoder errors.
		if clientConfig.WorkspaceCRN.Validate() != nil {
			diags.AddAttributeError(crnPath, "Invalid workspace CRN", "Use a workspace CRN with a supported region and a 16-character workspace ID.")
		} else {
			diags.AddAttributeError(keyPath, "Invalid access key", "Use an Admin access key with the CSAK prefix and an ID and secret separated by a dot.")
		}

		return nil
	}

	// CS_CTS_HOST replaces the workspace region's CTS, as in CipherStash's SDKs.
	// An empty value is unset; a malformed one fails rather than falling back.
	var authOptions []auth.Option
	var manageOptions []manage.ClientOption
	if host := os.Getenv("CS_CTS_HOST"); host != "" {
		ctsURL, err := url.Parse(host)
		if err != nil {
			diags.AddError("Invalid CTS host", invalidCTSHost)

			return nil
		}

		authOptions = append(authOptions, auth.WithCTSURL(ctsURL))
		manageOptions = append(manageOptions, manage.WithCTSURL(ctsURL))
	}

	// Token refresh outlives Configure, but the initial exchange must still
	// honour cancellation of this request. StopProvider cancels subsequent
	// resource requests through the framework and this authentication lifetime.
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	defer stop()

	tokens, err := auth.NewTokenSource(lifetime, clientConfig.WorkspaceCRN, clientConfig.ClientAccessKey, authOptions...)
	if errors.Is(err, auth.ErrConfig) && authOptions != nil {
		// The CRN and key are already valid, so the override was rejected.
		cancel()
		diags.AddError("Invalid CTS host", invalidCTSHost)

		return nil
	}

	if err == nil {
		_, err = tokens.Token()
	}

	if err != nil {
		cancel()
		diags.AddError("Cannot authenticate with CipherStash", "Could not verify an Admin token for the configured workspace. Check the CRN, credential and service connectivity. Control-only and Member-only credentials cannot configure this provider.")

		return nil
	}

	client, err := manage.NewClient(clientConfig.WorkspaceCRN, tokens, manageOptions...)
	if err != nil {
		cancel()
		diags.AddError("Cannot configure CipherStash client", "Could not initialize the service client for the configured workspace.")

		return nil
	}

	p.cancel = cancel

	return client
}

func (p *Provider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newActorResource, newClientResource, newKeysetResource, newKeysetGrantResource, newEQLResource}
}

func (p *Provider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newClientDataSource}
}

func (p *Provider) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.close()
}

func (p *Provider) close() {
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
}

// Framework 1.19 has no provider shutdown callback. Its supported protocol
// server seam lets us forward StopProvider cancellation before cancelling token
// refresh. main also closes when Serve returns (including managed debug).
func Protocol6(p *Provider) tfprotov6.ProviderServer {
	return &protocolServer{ProviderServer: providerserver.NewProtocol6(p)(), provider: p}
}

type protocolServer struct {
	tfprotov6.ProviderServer
	provider *Provider
}

func (s *protocolServer) StopProvider(ctx context.Context, req *tfprotov6.StopProviderRequest) (*tfprotov6.StopProviderResponse, error) {
	resp, err := s.ProviderServer.StopProvider(ctx, req)
	s.provider.Close()

	return resp, err
}

// This boundary is exactly the native operations used by resource reconciliation;
// tests can inject failures without a second HTTP/authentication implementation.
type manageClient interface {
	CreateCTSActor(context.Context, manage.CreateCTSActorOptions) (*manage.CreatedCTSActor, error)
	ListCTSActors(context.Context, manage.ListCTSActorsOptions) (manage.CTSActorPage, error)
	DeleteCTSActor(context.Context, string) error
	ListCTSAccessKeys(context.Context) ([]manage.CTSAccessKeyMetadata, error)
	CreateZeroKMSClient(context.Context, manage.CreateZeroKMSClientOptions) (*manage.CreatedZeroKMSClient, error)
	ListZeroKMSClients(context.Context, manage.ListZeroKMSClientsOptions) ([]manage.ZeroKMSClient, error)
	DeleteZeroKMSClient(context.Context, string) error
	GrantZeroKMSKeyset(context.Context, string, string) error
	RevokeZeroKMSKeyset(context.Context, string, string) error
	CreateZeroKMSKeyset(context.Context, manage.CreateZeroKMSKeysetOptions) (*manage.CreatedZeroKMSKeyset, error)
	ListZeroKMSKeysets(context.Context, manage.ListZeroKMSKeysetsOptions) ([]manage.ZeroKMSKeyset, error)
	ModifyZeroKMSKeyset(context.Context, string, manage.ModifyZeroKMSKeysetOptions) error
	EnableZeroKMSKeyset(context.Context, string) error
	DisableZeroKMSKeyset(context.Context, string) error
}

// The EQL operations resources use, one database connection each. Tests
// substitute a fake; postgresDatabase connects to a real server.
type eqlDatabase interface {
	InspectEQL(ctx context.Context, database string) (eql.Installation, error)
	InstallEQL(ctx context.Context, database, version string, requireORE bool) error
}

const invalidCTSHost = "CS_CTS_HOST must be an HTTPS URL, or HTTP to a loopback host such as http://localhost:3001, without credentials, query or fragment. Unset it to use the workspace region's CipherStash Token Service."

var (
	errNoAuth     = errors.New("provider auth settings are not configured")
	errNoDatabase = errors.New("provider database settings are not configured")
)

func clientFromProviderData(data any) (manageClient, error) {
	if data == nil {
		return nil, nil
	}

	settings, ok := data.(*providerData)
	if !ok {
		return nil, fmt.Errorf("unexpected provider data type %T", data)
	}

	if settings.manage == nil {
		return nil, errNoAuth
	}

	return settings.manage, nil
}

func databaseFromProviderData(data any) (eqlDatabase, error) {
	if data == nil {
		return nil, nil
	}

	settings, ok := data.(*providerData)
	if !ok {
		return nil, fmt.Errorf("unexpected provider data type %T", data)
	}

	if settings.database == nil {
		return nil, errNoDatabase
	}

	return settings.database, nil
}

// providerDataError reports an error from clientFromProviderData or
// databaseFromProviderData during resource or data source configuration.
func providerDataError(diags *diag.Diagnostics, err error) {
	switch {
	case errors.Is(err, errNoAuth):
		diags.AddError("Provider auth settings required", "This manages CipherStash objects, so the provider needs auth settings. Add auth = {} to use CS_WORKSPACE_CRN and CS_CLIENT_ACCESS_KEY, or set its arguments.")
	case errors.Is(err, errNoDatabase):
		diags.AddError("Provider database settings required", "This connects to PostgreSQL, so the provider needs database settings. Add database = { ... } to the provider configuration.")
	default:
		diags.AddError("Unexpected provider data", err.Error())
	}
}

// Never render upstream error text: service responses can echo submitted data.
func operationError(err error) string {
	httpErr, _ := errors.AsType[*manage.HTTPError](err)
	switch {
	case httpErr != nil && httpErr.StatusCode == http.StatusBadRequest:
		return "CipherStash rejected the request as invalid (HTTP 400). Retrying it unchanged will fail the same way."
	case errors.Is(err, manage.ErrForbidden):
		return "CipherStash denied this operation. Check the Admin credential and its permissions."
	case errors.Is(err, manage.ErrAuthentication):
		return "CipherStash authentication failed. Check the Admin credential and workspace CRN."
	case errors.Is(err, manage.ErrConflict):
		return "CipherStash reports a conflicting resource. Import the existing object or choose a different name."
	case errors.Is(err, manage.ErrNotFound):
		return "CipherStash could not find the requested object."
	case errors.Is(err, manage.ErrConfig):
		return "The CipherStash client rejected the operation configuration."
	default:
		return "The CipherStash operation failed. Check service availability before retrying; writes are not automatically retried."
	}
}
