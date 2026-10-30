package provider

import (
	"context"
	"errors"
	"slices"
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
		Description: "Create a ZeroKMS client and its client key in the configured workspace. This is a registered application client, not an SDK encryption-client object. Its client key is the application-held half of CipherStash's split key architecture.\n\nA new client receives access to the workspace's default keyset. This resource tracks that grant but does not manage additional grants created by Terraform or another tool. Changing any argument replaces the client and creates a new client key. Existing grants are not transferred to the replacement; plan the credential and grant changes before replacing a client. Creating a replacement does not establish when the old credential stops working.\n\nThe client key value is returned only at creation and stored in Terraform state and saved plans despite being marked sensitive. Import cannot recover it. Import with a client UUID requires exactly one existing grant. If the client has several grants, use `client UUID/keyset UUID` to select one. A client with no grants cannot be imported.",
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
				Computed:      true,
				Description:   "ID of the workspace's default keyset granted at creation, or the keyset selected from an existing grant during import. This value is computed, not configurable. The tracked grant must remain present; this resource leaves other grants unchanged.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
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
	if !slices.Contains(found.KeysetIDs, state.KeysetID.ValueString()) {
		resp.Diagnostics.AddError("Tracked client grant is missing", "The client still exists, but its recorded keyset grant is missing. State is retained. Restore the grant outside Terraform or deliberately replace the client; replacement loses all external grants.")
		return
	}

	// client_key is not readable; keep whatever state has.
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

// ImportState accepts a client UUID, or client UUID/keyset UUID to select an
// existing grant. Neither form can recover the creation secret.
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

	var keysetID string
	if len(parts) == 2 {
		keysetID = parts[1]
		if !slices.Contains(found.KeysetIDs, keysetID) {
			resp.Diagnostics.AddError("Invalid import grant", "The specified keyset is not granted to this client.")
			return
		}
	} else {
		if len(found.KeysetIDs) != 1 {
			resp.Diagnostics.AddError("Ambiguous import grant", "A client UUID alone requires exactly one grant. For several grants, use client UUID/keyset UUID to choose the tracked grant. A client without grants cannot be imported.")
			return
		}

		keysetID = found.KeysetIDs[0]
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, clientModel{
		ID: types.StringValue(found.ID), Name: types.StringValue(found.Name), Description: types.StringValue(found.Description),
		KeysetID: types.StringValue(keysetID), ClientKey: types.StringNull(),
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
