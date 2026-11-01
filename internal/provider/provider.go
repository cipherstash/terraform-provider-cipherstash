// Package provider manages CipherStash actors, clients, keysets and grants through native Go clients.
package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/auth"
	control "github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/manage"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/sethvargo/go-envconfig"
)

type Provider struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

func New() *Provider { return &Provider{} }

type providerModel struct {
	CRN       types.String `tfsdk:"workspace_crn"`
	AccessKey types.String `tfsdk:"client_access_key"`
}

func (p *Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "cipherstash"
}

func (p *Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use the CipherStash provider to manage machine identities, ZeroKMS clients, keysets, and keyset grants in a workspace. Configure a separate provider instance for each workspace. See the [workspace documentation](https://cipherstash.com/docs/reference/workspace) for the CipherStash concepts.\n\nThis provider is in development and is not published to the Terraform Registry. It uses this repository's public pkg/stack/auth and pkg/stack/manage Go packages. Builds require no BNDRY module, sibling SDK checkout, local module replacement or WebAssembly guest. The provider is licensed under the MIT License.\n\nAuthenticate with an Admin access key. The provider requires a verified Admin role even for configurations that manage only ZeroKMS resources or read data sources. Successful configuration does not prove permission for every operation. Create this credential outside the Terraform configuration that uses it. Resource access keys and client key values are stored in Terraform state and saved plans, even when marked sensitive. Protect these files and your state backend.\n\nNeither the provider nor manage.Config reads CS_CLIENT_ID: it identifies an application encryption client, not an authentication principal. Manage client/keyset pairs explicitly with cipherstash_zerokms_keyset_grant.",
		Attributes: map[string]schema.Attribute{
			"workspace_crn":     schema.StringAttribute{Optional: true, Description: "CipherStash Resource Name (CRN) of the workspace, in the format `crn:<region>.aws:<workspace ID>`. Omit this argument or set it to null to use `CS_WORKSPACE_CRN`. Explicit known values override the environment. Empty, unknown or malformed selected values are rejected without fallback; no saved profile is read. The old `crn` argument is not supported."},
			"client_access_key": schema.StringAttribute{Optional: true, Sensitive: true, Description: "Access key with the Admin role for this workspace. Omit this argument or set it to null to use `CS_CLIENT_ACCESS_KEY`. Explicit known values override the environment. Empty, unknown or malformed selected values are rejected without fallback. The old `access_key` and `control_access_key` arguments are not supported; `CS_CONTROL_ACCESS_KEY` and `CIPHERSTASH_ACCESS_KEY` are ignored. Native authentication verifies the token's signature, issuer, audience, expiry, workspace and Admin role before using it. Credentials without Admin, including Control-only and Member-only credentials, are rejected. CipherStash services authorize each request."},
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

	crnText := cfg.CRN.ValueString()
	if cfg.CRN.IsNull() {
		crnText = os.Getenv("CS_WORKSPACE_CRN")
	}

	if cfg.CRN.IsUnknown() || crnText == "" {
		resp.Diagnostics.AddAttributeError(path.Root("workspace_crn"), "Workspace CRN required", "Set workspace_crn or CS_WORKSPACE_CRN to a known workspace CRN. Explicit empty or unknown values do not use the environment fallback.")
	}

	keyText := cfg.AccessKey.ValueString()
	if cfg.AccessKey.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("client_access_key"), "Unknown access key", "The access key must be known before configuring this provider. Unknown values do not use the environment fallback.")
	} else {
		if cfg.AccessKey.IsNull() {
			keyText = os.Getenv("CS_CLIENT_ACCESS_KEY")
		}

		if keyText == "" {
			resp.Diagnostics.AddAttributeError(path.Root("client_access_key"), "Client access key required", "Set client_access_key or CS_CLIENT_ACCESS_KEY to an Admin key. Bootstrap this credential outside this Terraform root.")
		}
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Decode only the selected values, never falling back to the environment again.
	var clientConfig control.Config[auth.AdminAccessKey]
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
			resp.Diagnostics.AddAttributeError(path.Root("workspace_crn"), "Invalid workspace CRN", "Use a workspace CRN with a supported region and a 16-character workspace ID.")
		} else {
			resp.Diagnostics.AddAttributeError(path.Root("client_access_key"), "Invalid access key", "Use an Admin access key with the CSAK prefix and an ID and secret separated by a dot.")
		}

		return
	}

	// Token refresh outlives Configure, but the initial exchange must still
	// honour cancellation of this request. StopProvider cancels subsequent
	// resource requests through the framework and this authentication lifetime.
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	defer stop()

	tokens, err := auth.NewTokenSource(lifetime, clientConfig.WorkspaceCRN, clientConfig.ClientAccessKey)
	if err == nil {
		_, err = tokens.Token()
	}

	if err != nil {
		cancel()
		resp.Diagnostics.AddError("Cannot authenticate with CipherStash", "Could not verify an Admin token for the configured workspace. Check the CRN, credential and service connectivity. Control-only and Member-only credentials cannot configure this provider.")

		return
	}

	client, err := control.NewClient(clientConfig.WorkspaceCRN, tokens)
	if err != nil {
		cancel()
		resp.Diagnostics.AddError("Cannot configure CipherStash client", "Could not initialize the service client for the configured workspace.")

		return
	}

	p.cancel = cancel
	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *Provider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newActorResource, newClientResource, newKeysetResource, newKeysetGrantResource}
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
type controlClient interface {
	CreateCTSActor(context.Context, control.CreateCTSActorOptions) (*control.CreatedCTSActor, error)
	ListCTSActors(context.Context, control.ListCTSActorsOptions) (control.CTSActorPage, error)
	DeleteCTSActor(context.Context, string) error
	ListCTSAccessKeys(context.Context) ([]control.CTSAccessKeyMetadata, error)
	CreateZeroKMSClient(context.Context, control.CreateZeroKMSClientOptions) (*control.CreatedZeroKMSClient, error)
	ListZeroKMSClients(context.Context, control.ListZeroKMSClientsOptions) ([]control.ZeroKMSClient, error)
	DeleteZeroKMSClient(context.Context, string) error
	GrantZeroKMSKeyset(context.Context, string, string) error
	RevokeZeroKMSKeyset(context.Context, string, string) error
	CreateZeroKMSKeyset(context.Context, control.CreateZeroKMSKeysetOptions) (*control.CreatedZeroKMSKeyset, error)
	ListZeroKMSKeysets(context.Context, control.ListZeroKMSKeysetsOptions) ([]control.ZeroKMSKeyset, error)
	ModifyZeroKMSKeyset(context.Context, string, control.ModifyZeroKMSKeysetOptions) error
	EnableZeroKMSKeyset(context.Context, string) error
	DisableZeroKMSKeyset(context.Context, string) error
}

func clientFromProviderData(data any) (controlClient, error) {
	if data == nil {
		return nil, nil
	}

	client, ok := data.(controlClient)
	if !ok {
		return nil, fmt.Errorf("unexpected provider data type %T", data)
	}

	return client, nil
}

// Never render upstream error text: service responses can echo submitted data.
func operationError(err error) string {
	switch {
	case errors.Is(err, control.ErrForbidden):
		return "CipherStash denied this operation. Check the Admin credential and its permissions."
	case errors.Is(err, control.ErrAuthentication):
		return "CipherStash authentication failed. Check the Admin credential and workspace CRN."
	case errors.Is(err, control.ErrConflict):
		return "CipherStash reports a conflicting resource. Import the existing object or choose a different name."
	case errors.Is(err, control.ErrNotFound):
		return "CipherStash could not find the requested object."
	case errors.Is(err, control.ErrConfig):
		return "The CipherStash client rejected the operation configuration."
	default:
		return "The CipherStash operation failed. Check service availability before retrying; writes are not automatically retried."
	}
}
