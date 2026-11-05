package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/manage"
)

type clientResource struct {
	client manageClient
}

var (
	_ resource.ResourceWithConfigure   = &clientResource{}
	_ resource.ResourceWithImportState = &clientResource{}
)

func newClientResource() resource.Resource { return &clientResource{} }

type clientModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	ClientKey   types.String `tfsdk:"client_key"`
}

func (r *clientResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_zerokms_client"
}

func (r *clientResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Create a ZeroKMS client and its client key in the configured workspace. This is a registered application client, not an SDK encryption-client object. Its client key is the application-held half of CipherStash's split key architecture.\n\nCreate does not choose a keyset, so CipherStash creates the workspace's default keyset if needed and grants the new client access to it. CipherStash owns that keyset and grant; you do not need to import or manage either. This resource manages the client identity, not its grants. Use `cipherstash_zerokms_keyset_grant` for access to keysets you manage. Refresh and import never change grants or the default keyset, delete removes only the client, and a client remains managed even with no grants. Changing name or description replaces the client and creates a new client key. Existing grants are not transferred to the replacement; plan the credential and grant changes before replacing a client. Creating a replacement does not establish when the old credential stops working.\n\nThe client key value is returned only at creation and stored in Terraform state and saved plans despite being marked sensitive. Import by client UUID, whatever grants the client has; import cannot recover the client key, so it is null afterward. Use the `cipherstash_zerokms_client` data source's `keyset_ids` for current grant inventory.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Client ID as a UUID. Use this value for `CS_CLIENT_ID` in your application.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "Name of the ZeroKMS client. Changing this value replaces the client.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"description": schema.StringAttribute{
				Required:      true,
				Description:   "Description of the ZeroKMS client. Changing this value replaces the client.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"client_key": schema.StringAttribute{
				Computed:      true,
				Sensitive:     true,
				Description:   "Secret client key for CS_CLIENT_KEY, returned as base64 at creation. Null after import, because CipherStash returns the key only at creation. Refresh retains it. Sensitive values remain in state and saved plans.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *clientResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		providerDataError(&resp.Diagnostics, err)
		return
	}

	r.client = client
}

func (r *clientResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan clientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	created, err := r.client.CreateZeroKMSClient(ctx, manage.CreateZeroKMSClientOptions{Name: plan.Name.ValueString(), Description: plan.Description.ValueString()})
	if err != nil {
		resp.Diagnostics.AddError("Cannot create client", operationError(err))
		return
	}
	defer created.Wipe()

	plan.ID = types.StringValue(created.ID)
	plan.ClientKey = types.StringNull()
	secret, err := created.ExportClientKey()
	if err == nil {
		plan.ClientKey = types.StringValue(string(secret))
	}

	clear(secret)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if err != nil {
		resp.Diagnostics.AddError("Cannot export client key", "The client ID is saved in state, but its secret could not be exported. Replace the client to obtain a new secret.")
	}
}

func (r *clientResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state clientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	found, err := r.findClient(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot read client", operationError(err))
		return
	}

	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.Name = types.StringValue(found.Name)
	state.Description = types.StringValue(found.Description)

	// Keep the one-time secret; grants are not part of this resource.
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *clientResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Clients cannot be updated in place", "This is a provider bug: all arguments are marked RequiresReplace.")
}

func (r *clientResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state clientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteZeroKMSClient(ctx, state.ID.ValueString()); err != nil && !errors.Is(err, manage.ErrNotFound) {
		resp.Diagnostics.AddError("Cannot delete client", operationError(err))
	}
}

// ImportState accepts a client UUID and never changes grants.
func (r *clientResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if _, err := uuid.ParseUUID(req.ID); err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Use the client UUID.")
		return
	}

	found, err := r.findClient(ctx, req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Cannot import client", operationError(err))
		return
	}

	if found == nil {
		resp.Diagnostics.AddError("Cannot import client", "No client with this UUID exists in the configured workspace.")
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, clientModel{
		ID: types.StringValue(found.ID), Name: types.StringValue(found.Name), Description: types.StringValue(found.Description),
		ClientKey: types.StringNull(),
	})...)
}

func (r *clientResource) findClient(ctx context.Context, id string) (*manage.ZeroKMSClient, error) {
	clients, err := r.client.ListZeroKMSClients(ctx, manage.ListZeroKMSClientsOptions{})
	if err != nil {
		return nil, err
	}

	for _, client := range clients {
		if client.ID == id {
			return &client, nil
		}
	}

	return nil, nil
}
