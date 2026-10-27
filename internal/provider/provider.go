// Package provider manages CipherStash actors, clients, keysets and grants through the Go SDK.
package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/control"
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
	mu       sync.Mutex
	store    *auth.ProfileStore
	strategy *auth.Strategy
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
		Description: "Use the CipherStash provider to manage machine identities, ZeroKMS clients, keysets, and keyset grants in a workspace. Configure a separate provider instance for each workspace. See the [workspace documentation](https://cipherstash.com/docs/reference/workspace) for the CipherStash concepts.\n\nThis provider is in development and is not published to the Terraform Registry. Local builds require a coordinated CipherStash Go SDK checkout. SDK distribution and provider licensing remain unresolved.\n\nAuthenticate with an access key that has the Admin role. Create this credential outside the Terraform configuration that uses it. Resource access keys and client key values are stored in Terraform state and saved plans, even when marked sensitive. Protect these files and your state backend.",
		Attributes: map[string]schema.Attribute{
			"crn":        schema.StringAttribute{Required: true, Description: "CipherStash Resource Name (CRN) of the workspace, in the format `crn:<region>.aws:<workspace ID>`. Set this explicitly; the provider does not read it from an environment variable or saved profile."},
			"access_key": schema.StringAttribute{Optional: true, Sensitive: true, Description: "Access key with the Admin role for this workspace. Omit this argument or set it to null to use `CIPHERSTASH_ACCESS_KEY`. Empty strings and values that are unknown during provider configuration are rejected. The SDK checks the role in the decoded token as a configuration guard; this is not signature verification or authorization. CipherStash services authorize each request."},
		},
	}
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.close(); err != nil {
		resp.Diagnostics.AddError("Cannot release prior authentication", "The SDK could not close the previous authentication session.")
		return
	}

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

	key := auth.NewAccessKey([]byte(keyText))
	defer key.Wipe()

	store, err := auth.OpenWithoutProfile(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Cannot open authentication", "The SDK could not initialize its credential guest.")
		return
	}

	strategy, err := store.AccessKey(ctx, cfg.CRN.ValueString(), key, auth.WithAcceptedRoles("Admin"))
	if err != nil {
		resp.Diagnostics.AddError("Cannot configure authentication", "The SDK rejected the CRN or authentication configuration.")
		if closeErr := store.Close(); closeErr != nil {
			resp.Diagnostics.AddError("Cannot release authentication", "The SDK could not close the failed authentication session.")
		}

		return
	}

	client, err := control.NewClient(ctx, cfg.CRN.ValueString(), control.WithCTSAuth(strategy), control.WithZeroKMSAuth(strategy))
	if err != nil {
		resp.Diagnostics.AddError("Cannot authenticate with CipherStash", "The SDK could not initialize the service client for the configured workspace. Check the CRN, credential and service connectivity.")
		if closeErr := errors.Join(strategy.Close(), store.Close()); closeErr != nil {
			resp.Diagnostics.AddError("Cannot release authentication", "The SDK could not close the failed authentication session.")
		}

		return
	}

	p.store, p.strategy = store, strategy
	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *Provider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newActorResource, newClientResource, newKeysetResource, newKeysetGrantResource}
}

func (p *Provider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newClientDataSource}
}

func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.close()
}

func (p *Provider) close() error {
	var err error
	if p.strategy != nil {
		err = p.strategy.Close()
		p.strategy = nil
	}

	if p.store != nil {
		err = errors.Join(err, p.store.Close())
		p.store = nil
	}

	return err
}

// Framework 1.19 has no provider shutdown callback. Its supported protocol
// server seam lets us forward StopProvider cancellation before releasing SDK
// ownership. main also closes when Serve returns (including managed debug).
func Protocol6(p *Provider) tfprotov6.ProviderServer {
	return &protocolServer{ProviderServer: providerserver.NewProtocol6(p)(), provider: p}
}

type protocolServer struct {
	tfprotov6.ProviderServer
	provider *Provider
}

func (s *protocolServer) StopProvider(ctx context.Context, req *tfprotov6.StopProviderRequest) (*tfprotov6.StopProviderResponse, error) {
	resp, err := s.ProviderServer.StopProvider(ctx, req)
	if closeErr := s.provider.Close(); closeErr != nil {
		return resp, errors.Join(err, errors.New("could not close SDK authentication"))
	}

	return resp, err
}

// This boundary is exactly the SDK operations used by resource reconciliation;
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
		return "The SDK rejected the operation configuration."
	default:
		return "The CipherStash operation failed. Check service availability before retrying; writes are not automatically retried."
	}
}
