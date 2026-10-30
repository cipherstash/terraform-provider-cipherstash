// Package provider manages CipherStash actors, clients, keysets and grants through native Go clients.
package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/auth"
	control "github.com/cipherstash/terraform-provider-cipherstash/internal/stack/manage"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

type Provider struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

func New() *Provider { return &Provider{} }

type providerModel struct {
	CRN       types.String `tfsdk:"crn"`
	AccessKey types.String `tfsdk:"access_key"`
}

func (p *Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "cipherstash"
}

func (p *Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use the CipherStash provider to manage machine identities, ZeroKMS clients, keysets, and keyset grants in a workspace. Configure a separate provider instance for each workspace. See the [workspace documentation](https://cipherstash.com/docs/reference/workspace) for the CipherStash concepts.\n\nThis provider is in development and is not published to the Terraform Registry. Local builds use the native Go authentication and management packages in this repository; no separate SDK checkout or WebAssembly guest is required. Provider licensing remains unresolved.\n\nAuthenticate with an access key that has the Admin role. Create this credential outside the Terraform configuration that uses it. Resource access keys and client key values are stored in Terraform state and saved plans, even when marked sensitive. Protect these files and your state backend.",
		Attributes: map[string]schema.Attribute{
			"crn":        schema.StringAttribute{Required: true, Description: "CipherStash Resource Name (CRN) of the workspace, in the format `crn:<region>.aws:<workspace ID>`. Set this explicitly; the provider does not read it from an environment variable or saved profile."},
			"access_key": schema.StringAttribute{Optional: true, Sensitive: true, Description: "Access key with the Admin role for this workspace. Omit this argument or set it to null to use `CIPHERSTASH_ACCESS_KEY`. Empty strings and values that are unknown during provider configuration are rejected. Native authentication verifies the token's signature, issuer, audience, expiry, workspace and Admin role before using it. CipherStash services authorize each request."},
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

	if cfg.CRN.IsUnknown() || cfg.CRN.IsNull() || cfg.CRN.ValueString() == "" {
		resp.Diagnostics.AddAttributeError(path.Root("crn"), "Workspace CRN required", "Set an explicit, known workspace CRN before configuring this provider.")
	}

	keyText := cfg.AccessKey.ValueString()
	if cfg.AccessKey.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("access_key"), "Unknown access key", "The access key must be known before configuring this provider. Unknown values do not use the environment fallback.")
	} else {
		if cfg.AccessKey.IsNull() {
			keyText = os.Getenv("CIPHERSTASH_ACCESS_KEY")
		}

		if keyText == "" {
			resp.Diagnostics.AddAttributeError(path.Root("access_key"), "Admin access key required", "Set access_key or CIPHERSTASH_ACCESS_KEY. Bootstrap this credential outside this Terraform root.")
		}
	}

	if resp.Diagnostics.HasError() {
		return
	}

	crn, err := auth.ParseCRN(cfg.CRN.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("crn"), "Invalid workspace CRN", "Use a workspace CRN with a supported region and a 16-character workspace ID.")
		return
	}

	key, err := auth.ParseAdminAccessKey(keyText)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("access_key"), "Invalid access key", "Use an Admin access key with the CSAK prefix and an ID and secret separated by a dot.")
		return
	}

	// Token refresh outlives Configure, but the initial exchange must still
	// honour cancellation of this request. StopProvider cancels subsequent
	// resource requests through the framework and this authentication lifetime.
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	defer stop()

	tokens, err := auth.NewTokenSource(lifetime, crn, key)
	if err == nil {
		_, err = tokens.Token()
	}

	if err != nil {
		cancel()
		resp.Diagnostics.AddError("Cannot authenticate with CipherStash", "Could not verify an Admin token for the configured workspace. Check the CRN, credential and service connectivity.")

		return
	}

	client, err := control.NewClient(crn, tokens)
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
	CreateActor(context.Context, control.CreateActorOptions) (*control.CreatedActor, error)
	ListActors(context.Context, control.ListActorsOptions) (control.ActorPage, error)
	DeleteActor(context.Context, string) error
	ListAccessKeys(context.Context) ([]control.AccessKeyMetadata, error)
	CreateClient(context.Context, control.CreateClientOptions) (*control.CreatedClient, error)
	ListClients(context.Context, control.ListClientsOptions) ([]control.EncryptionClient, error)
	DeleteClient(context.Context, string) error
	GrantKeyset(context.Context, string, string) error
	RevokeKeyset(context.Context, string, string) error
	CreateKeyset(context.Context, control.CreateKeysetOptions) (*control.CreatedKeyset, error)
	ListKeysets(context.Context, control.ListKeysetsOptions) ([]control.Keyset, error)
	ModifyKeyset(context.Context, string, control.ModifyKeysetOptions) error
	EnableKeyset(context.Context, string) error
	DisableKeyset(context.Context, string) error
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
