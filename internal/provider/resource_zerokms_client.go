package provider

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	control "github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/manage"
)

type clientResource struct {
	client controlClient
}

var (
	_ resource.ResourceWithConfigure   = &clientResource{}
	_ resource.ResourceWithImportState = &clientResource{}
	_ resource.ResourceWithModifyPlan  = &clientResource{}
)

func newClientResource() resource.Resource { return &clientResource{} }

type clientModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Description       types.String `tfsdk:"description"`
	KeysetID          types.String `tfsdk:"keyset_id"`
	ClientKey         types.String `tfsdk:"client_key"`
	ClientKeyClientID types.String `tfsdk:"client_key_client_id"`
}

func (r *clientResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_zerokms_client"
}

func (r *clientResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Create a ZeroKMS client and its client key in the configured workspace. This is a registered application client, not an SDK encryption-client object. Its client key is the application-held half of CipherStash's split key architecture.\n\nA new client receives access to the workspace's default keyset. This resource manages the client identity, not its grants. Import existing pairs into `cipherstash_zerokms_keyset_grant` to manage them explicitly, including the automatic default grant. Refresh and import never change grants, and a client remains managed even with no grants. Changing name or description replaces the client and creates a new client key. Existing grants are not transferred to the replacement; plan the credential and grant changes before replacing a client. Creating a replacement does not establish when the old credential stops working.\n\nThe client key value is returned only at creation and stored in Terraform state and saved plans despite being marked sensitive. Import cannot recover it. Import by client UUID with zero, one or many grants; `keyset_id` is null for these imports. Legacy `client UUID/keyset UUID` imports retain the second UUID as historical metadata only, without checking or managing that grant. Use the `cipherstash_zerokms_client` data source's `keyset_ids` for current grant inventory.\n\nAfter import, you may supply an existing `client_key` with an explicit `client_key_client_id` matching the managed UUID. Applying records the key in state without a CipherStash write; it does not rotate a key or change grants. The provider checks key format, UUID equality and client existence, not cryptographic ownership. Verify the key/client pairing separately. A different persisted key is rejected. Both inputs must be known during planning. Creation and replacement are rejected while either seed argument is configured. Remove both arguments before intentional replacement; removal alone retains the key in state. Terraform's `ignore_changes` applies normally: ignored key changes retain state, rather than being adopted or rejected. No import provenance is inferred from a null key.",
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
				DeprecationMessage: "Use the cipherstash_zerokms_client data source's keyset_ids for current grants and cipherstash_zerokms_keyset_grant to manage individual pairs. keyset_id is historical metadata only.",
				PlanModifiers:      []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"client_key": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Sensitive:     true,
				Description:   "Secret client key for CS_CLIENT_KEY. Returned as base64 at creation; null after import unless subsequently seeded. To seed an existing client's missing key, supply its generated v1 CBOR permutation keyset, encoded as standard base64 or hex, and client_key_client_id. The supplied encoding is preserved exactly. This only records state, does not rotate credentials, and cannot verify key ownership. Refresh and configuration removal retain the key. Sensitive values remain in state and saved plans.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"client_key_client_id": schema.StringAttribute{
				Optional:    true,
				Description: "Expected existing client UUID for the supplied client_key. Must be known and match the managed id. Use an independently supplied UUID, not this resource's own id, so importing a different client cannot silently reuse the seed. This assertion does not prove key ownership. Remove both seed arguments before intentional replacement.",
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

// Validate the named-map format emitted by recipher 0.3.1 ProxyKeySet::to_bytes,
// including its generated permutation invariants, not every representation its
// permissive Serde decoder accepts. There is no client identity in this format.
func validClientKey(encoded string) bool {
	key, err := hex.DecodeString(encoded) // Stack's from_encoded_v1 tries hex first.
	if err != nil {
		clear(key)
		if strings.ContainsAny(encoded, "\r\n") {
			return false // Go base64 otherwise ignores these; Stack does not.
		}
		key, err = base64.StdEncoding.Strict().DecodeString(encoded)
	}
	defer clear(key)
	if err != nil {
		return false
	}
	decoder, err := (cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
	}).DecMode()
	if err != nil {
		panic(err) // Constant decoder options, not user input.
	}
	// Check field-name types explicitly: decoding into string keys coerces
	// CBOR null to "", and Serde treats integer names as known-field aliases.
	var permutations map[any]cbor.RawMessage
	if err := decoder.Unmarshal(key, &permutations); err != nil {
		return false
	}
	for name := range permutations {
		if _, ok := name.(string); !ok {
			return false
		}
	}
	for i, name := range []string{"p1", "p2_from", "p2_to", "p3"} {
		var permutation map[any]cbor.RawMessage
		if err := decoder.Unmarshal(permutations[name], &permutation); err != nil {
			return false
		}
		for name := range permutation {
			if _, ok := name.(string); !ok {
				return false
			}
		}
		var values []any
		if err := decoder.Unmarshal(permutation["permutation"], &values); err != nil {
			return false
		}
		size := 16
		if i == 3 {
			size = 33
		}
		if len(values) != size {
			return false
		}
		seen := uint64(0)
		for _, value := range values {
			index, ok := value.(uint64)
			if !ok || index >= uint64(size) || seen&(1<<index) != 0 {
				return false
			}
			seen |= 1 << index
		}
	}
	return true
}

func (r *clientResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}

	var config, state, plan clientModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || (config.ClientKey.IsNull() && config.ClientKeyClientID.IsNull()) {
		return
	}

	if config.ClientKey.IsUnknown() || config.ClientKeyClientID.IsUnknown() {
		resp.Diagnostics.AddError("Cannot seed client key", "client_key and client_key_client_id must be known during planning.")
		return
	}
	if req.State.Raw.IsNull() {
		// Terraform replans replacements with null prior state before Delete,
		// including taint and -replace. A Create-only guard would be too late.
		resp.Diagnostics.AddError("Cannot seed client key", "Seed arguments cannot create or replace a client. Import an existing client first, or remove both seed arguments before intentional replacement.")
		return
	}

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// ignore_changes can put the persisted key into the effective config even
	// when no seed was configured. Retaining that key needs no UUID assertion.
	retainingKey := !state.ClientKey.IsNull() && config.ClientKey.Equal(state.ClientKey)
	if (config.ClientKeyClientID.IsNull() && !retainingKey) ||
		(!config.ClientKeyClientID.IsNull() && !config.ClientKeyClientID.Equal(state.ID)) {
		resp.Diagnostics.AddAttributeError(path.Root("client_key_client_id"), "Cannot seed client key", "Supply an explicit client_key_client_id matching the managed client UUID.")
		return
	}
	if !config.ClientKey.IsNull() && !retainingKey {
		if !validClientKey(config.ClientKey.ValueString()) {
			resp.Diagnostics.AddError("Cannot seed client key", "Supply a generated v1 CBOR permutation client key encoded as standard base64 or hex. Format validation does not prove which client owns it.")
			return
		}
		if !state.ClientKey.IsNull() && !state.ClientKey.Equal(config.ClientKey) {
			resp.Diagnostics.AddError("Cannot seed client key", "The supplied key differs from the persisted key. Seeding is not key rotation.")
			return
		}
	}
	// Retention alone must not block replacement. Terraform replans it with
	// null prior state and the original config, where configured seeds reject.
	if (!retainingKey || !config.ClientKeyClientID.IsNull()) &&
		(!state.Name.Equal(plan.Name) || !state.Description.Equal(plan.Description)) {
		resp.Diagnostics.AddError("Cannot seed client key", "Changing client metadata requires replacement. Remove both seed arguments before intentional replacement.")
	}
}

func (r *clientResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var config, plan clientModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.ClientKey.IsNull() || !config.ClientKeyClientID.IsNull() {
		resp.Diagnostics.AddError("Cannot seed client key", "Seed arguments cannot create or replace a client.")
		return
	}

	created, err := r.client.CreateZeroKMSClient(ctx, control.CreateZeroKMSClientOptions{Name: plan.Name.ValueString(), Description: plan.Description.ValueString()})
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

// Update records a supplied secret or removes its UUID assertion, never writes
// to CipherStash. Terraform has already validated the effective configuration.
func (r *clientResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var state, plan clientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !state.ID.Equal(plan.ID) || !state.Name.Equal(plan.Name) || !state.Description.Equal(plan.Description) ||
		(!state.ClientKey.IsNull() && !state.ClientKey.Equal(plan.ClientKey)) ||
		(!plan.ClientKeyClientID.IsNull() && !plan.ClientKeyClientID.Equal(state.ID)) ||
		(!state.ClientKey.Equal(plan.ClientKey) && !plan.ClientKeyClientID.Equal(state.ID)) {
		resp.Diagnostics.AddError("Cannot seed client key", "Only the matching existing client may adopt a missing key; its identity, metadata and persisted key cannot change.")
		return
	}

	// A saved plan may outlive the remote client. Do not recreate it or record
	// a secret for an absent identity when that plan is applied.
	found, err := r.findClient(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot read client", operationError(err))
		return
	}
	if found == nil {
		resp.Diagnostics.AddError("Cannot seed client key", "The planned client no longer exists. Refresh and review the plan; no key was adopted.")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *clientResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state clientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteZeroKMSClient(ctx, state.ID.ValueString()); err != nil && !errors.Is(err, control.ErrNotFound) {
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

func (r *clientResource) findClient(ctx context.Context, id string) (*control.ZeroKMSClient, error) {
	clients, err := r.client.ListZeroKMSClients(ctx, control.ListZeroKMSClientsOptions{})
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
