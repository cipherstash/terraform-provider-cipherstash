package provider

import (
	"context"
	"regexp"
	"slices"
	"strings"

	control "github.com/cipherstash/terraform-provider-cipherstash/internal/stack/manage"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type keysetGrantResource struct {
	client controlClient
}

var (
	_ resource.ResourceWithConfigure   = &keysetGrantResource{}
	_ resource.ResourceWithImportState = &keysetGrantResource{}
)

func newKeysetGrantResource() resource.Resource { return &keysetGrantResource{} }

type keysetGrantModel struct {
	ID       types.String `tfsdk:"id"`
	ClientID types.String `tfsdk:"client_id"`
	KeysetID types.String `tfsdk:"keyset_id"`
}

func (r *keysetGrantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keyset_grant"
}

func (r *keysetGrantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	uuidValidator := stringvalidator.RegexMatches(regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`), "must be a lowercase UUID")
	resp.Schema = schema.Schema{
		Description: "Grant a ZeroKMS client access to one keyset. This resource manages a single client/keyset pair, not the client's full set of grants. Your application must still select the keyset in its SDK configuration.\n\nDestroy revokes only this grant; it does not delete the client or keyset, or change other grants. Changing either ID replaces the grant without transferring any other grants.\n\nGive each pair one owner. Do not manage it from another Terraform resource, state, or provisioning worker. Import an existing pair rather than creating it again. Do not separately manage the grant tracked by a `cipherstash_client` resource, including its automatic default-keyset grant; that resource requires the grant to remain present.\n\nLocal tests cover this resource, but its lifecycle has not been verified against the live service. Earlier live grant and revoke probes returned HTTP 500 with the default grant unchanged.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Grant ID in the format `client UUID/keyset UUID`. Use the same format to import an existing grant.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"client_id": schema.StringAttribute{
				Required:      true,
				Description:   "ID of an existing ZeroKMS client, as a lowercase UUID. Changing this value replaces the grant; it does not copy the client's other grants.",
				Validators:    []validator.String{uuidValidator},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"keyset_id": schema.StringAttribute{
				Required:      true,
				Description:   "ID of an existing keyset, as a lowercase UUID. Changing this value replaces the grant. A disabled keyset can still have grants; a grant does not enable it.",
				Validators:    []validator.String{uuidValidator},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
	}
}

func (r *keysetGrantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}

	r.client = client
}

func (r *keysetGrantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan keysetGrantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exists, err := r.hasGrant(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Cannot inspect existing grants", operationError(err))
		return
	}

	if exists {
		resp.Diagnostics.AddError("Grant already exists", "Import this client UUID/keyset UUID pair to take ownership. Creating a resource must not silently adopt an existing worker-managed or default grant.")
		return
	}

	writeErr := r.client.GrantKeyset(ctx, plan.KeysetID.ValueString(), plan.ClientID.ValueString())
	plan.ID = types.StringValue(plan.ClientID.ValueString() + "/" + plan.KeysetID.ValueString())
	// The identity is known even if the write response was lost. Keep it before
	// readback so a failed read cannot discard a potentially created grant.
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	exists, readErr := r.hasGrant(ctx, plan)
	if writeErr != nil {
		if readErr == nil && !exists {
			resp.State.RemoveResource(ctx)
		}

		resp.Diagnostics.AddError("Cannot create keyset grant", operationError(writeErr)+" A readback was attempted without retrying the write. If the pair remains in state, inspect it and the next plan before retrying: Terraform may mark it tainted.")

		return
	}

	if readErr != nil {
		resp.Diagnostics.AddError("Cannot confirm keyset grant", operationError(readErr)+" The pair is retained in state.")
		return
	}

	if !exists {
		resp.Diagnostics.AddError("Keyset grant not visible", "CipherStash accepted the grant but it was not present in the subsequent inventory. The pair is retained in state; inspect inventory before retrying.")
	}
}

func (r *keysetGrantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state keysetGrantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exists, err := r.hasGrant(ctx, state)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read keyset grant", operationError(err))
		return
	}

	if !exists {
		resp.State.RemoveResource(ctx)
	}
}

func (r *keysetGrantResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Grants cannot be updated in place", "This is a provider bug: both identifiers are marked RequiresReplace.")
}

func (r *keysetGrantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state keysetGrantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exists, err := r.hasGrant(ctx, state)
	if err != nil {
		resp.Diagnostics.AddError("Cannot inspect keyset grant", operationError(err))
		return
	}

	if !exists {
		return
	}

	writeErr := r.client.RevokeKeyset(ctx, state.KeysetID.ValueString(), state.ClientID.ValueString())
	exists, readErr := r.hasGrant(ctx, state)
	if readErr != nil {
		resp.Diagnostics.AddError("Cannot confirm grant revocation", operationError(readErr)+" State is retained because the pair's absence could not be confirmed.")
		return
	}

	if !exists {
		if writeErr != nil {
			resp.Diagnostics.AddWarning("Grant absence confirmed after revocation error", "The revoke request returned an error, but independent inventory confirms this pair is absent. No write was retried.")
		}

		return
	}

	if writeErr != nil {
		resp.Diagnostics.AddError("Cannot revoke keyset grant", operationError(writeErr)+" The pair still exists and is retained in state.")
		return
	}

	resp.Diagnostics.AddError("Keyset grant still present", "CipherStash accepted the revocation but the pair remains in inventory. State is retained; inspect inventory before retrying.")
}

func (r *keysetGrantResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(strings.ToLower(req.ID), "/")
	if len(parts) != 2 {
		resp.Diagnostics.AddError("Invalid import ID", "Use client UUID/keyset UUID to identify one existing grant.")
		return
	}

	for _, part := range parts {
		if _, err := uuid.ParseUUID(part); err != nil {
			resp.Diagnostics.AddError("Invalid import ID", "Client and keyset identifiers must be UUIDs.")
			return
		}
	}

	state := keysetGrantModel{ID: types.StringValue(strings.Join(parts, "/")), ClientID: types.StringValue(parts[0]), KeysetID: types.StringValue(parts[1])}
	exists, err := r.hasGrant(ctx, state)
	if err != nil {
		resp.Diagnostics.AddError("Cannot import keyset grant", operationError(err))
		return
	}

	if !exists {
		resp.Diagnostics.AddError("Keyset grant not found", "This client/keyset pair is not granted in the configured workspace. Import does not create grants.")
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *keysetGrantResource) hasGrant(ctx context.Context, state keysetGrantModel) (bool, error) {
	clients, err := r.client.ListClients(ctx, control.ListClientsOptions{})
	if err != nil {
		return false, err
	}

	for _, client := range clients {
		if client.ID == state.ClientID.ValueString() {
			return slices.Contains(client.KeysetIDs, state.KeysetID.ValueString()), nil
		}
	}

	return false, nil
}
