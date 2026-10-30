package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	control "github.com/cipherstash/terraform-provider-cipherstash/internal/stack/manage"
)

type clientResource struct {
	client controlClient
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
	KeysetID    types.String `tfsdk:"keyset_id"`
	ClientKey   types.String `tfsdk:"client_key"`
}

func (r *clientResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_client"
}

func (r *clientResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Create a ZeroKMS client and its client key in the configured workspace. This is a registered application client, not an SDK encryption-client object. Its client key is the application-held half of CipherStash's split key architecture.\n\nA new client receives access to the workspace's default keyset. This resource manages the client identity, not its grants. Import existing pairs into `cipherstash_keyset_grant` to manage them explicitly, including the automatic default grant. Refresh and import never change grants, and a client remains managed even with no grants. Changing name or description replaces the client and creates a new client key. Existing grants are not transferred to the replacement; plan the credential and grant changes before replacing a client. Creating a replacement does not establish when the old credential stops working.\n\nThe client key value is returned only at creation and stored in Terraform state and saved plans despite being marked sensitive. Import cannot recover it. Import by client UUID with zero, one or many grants; `keyset_id` is null for these imports. Legacy `client UUID/keyset UUID` imports retain the second UUID as historical metadata only, without checking or managing that grant. Use the `cipherstash_client` data source's `keyset_ids` for current grant inventory.",
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
			"keyset_id": schema.StringAttribute{
				Computed:           true,
				Description:        "Deprecated historical metadata: the default keyset ID returned at creation, or the second UUID supplied to a legacy pair import. Existing state values are preserved even if the grant disappears. Null for new UUID-only imports, regardless of grant count. This value is computed, not configurable, and does not describe current access or imply grant ownership.",
				DeprecationMessage: "Use the cipherstash_client data source's keyset_ids for current grants and cipherstash_keyset_grant to manage individual pairs. keyset_id is historical metadata only.",
				PlanModifiers:      []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"client_key": schema.StringAttribute{
				Computed:      true,
				Sensitive:     true,
				Description:   "Secret client key value, encoded as base64 for `CS_CLIENT_KEY` in the coordinated Go SDK. Returned only at creation and retained in Terraform state; null after import. Marking it sensitive does not remove it from state or saved plans. Follow your application's SDK requirements for key encoding.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *clientResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
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

	created, err := r.client.CreateClient(ctx, control.CreateClientOptions{Name: plan.Name.ValueString(), Description: plan.Description.ValueString()})
	if err != nil {
		resp.Diagnostics.AddError("Cannot create client", operationError(err))
		return
	}
	defer created.Wipe()

	plan.ID = types.StringValue(created.ID)
	plan.KeysetID = types.StringValue(created.KeysetID)
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

	// Keep the one-time secret and historical keyset metadata, not live grants.
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update is never called: every argument requires replacement.
func (r *clientResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Clients cannot be updated in place", "This is a provider bug: all arguments are marked RequiresReplace.")
}

func (r *clientResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state clientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteClient(ctx, state.ID.ValueString()); err != nil && !errors.Is(err, control.ErrNotFound) {
		resp.Diagnostics.AddError("Cannot delete client", operationError(err))
	}
}

// ImportState accepts a client UUID, or a legacy client UUID/keyset UUID whose
// second component is historical metadata only. Neither form changes grants.
func (r *clientResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if len(parts) < 1 || len(parts) > 2 {
		resp.Diagnostics.AddError("Invalid import ID", "Use client UUID or client UUID/keyset UUID.")
		return
	}

	for _, part := range parts {
		if _, err := uuid.ParseUUID(part); err != nil {
			resp.Diagnostics.AddError("Invalid import ID", "Client and keyset identifiers must be UUIDs.")
			return
		}
	}

	found, err := r.findClient(ctx, parts[0])
	if err != nil {
		resp.Diagnostics.AddError("Cannot import client", operationError(err))
		return
	}

	if found == nil {
		resp.Diagnostics.AddError("Cannot import client", "No client with this UUID exists in the configured workspace.")
		return
	}

	keysetID := types.StringNull()
	if len(parts) == 2 {
		keysetID = types.StringValue(parts[1])
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, clientModel{
		ID: types.StringValue(found.ID), Name: types.StringValue(found.Name), Description: types.StringValue(found.Description),
		KeysetID: keysetID, ClientKey: types.StringNull(),
	})...)
}

func (r *clientResource) findClient(ctx context.Context, id string) (*control.EncryptionClient, error) {
	clients, err := r.client.ListClients(ctx, control.ListClientsOptions{})
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
