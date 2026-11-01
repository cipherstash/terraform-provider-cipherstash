package provider

import (
	"context"
	"errors"
	"regexp"
	"strings"

	control "github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/manage"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type keysetResource struct {
	client controlClient
}

var (
	_ resource.ResourceWithConfigure   = &keysetResource{}
	_ resource.ResourceWithImportState = &keysetResource{}
	_ resource.ResourceWithModifyPlan  = &keysetResource{}
)

func newKeysetResource() resource.Resource { return &keysetResource{} }

type keysetModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	IsDefault   types.Bool   `tfsdk:"is_default"`
}

func (r *keysetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_zerokms_keyset"
}

func (r *keysetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Create and manage a keyset in ZeroKMS. A keyset is an independent authority-key scope: clients must be granted access to use it. This resource manages the keyset's name, description, and enabled status without creating a client or grant. Use `cipherstash_zerokms_keyset_grant` to grant access separately.\n\nChanges update the existing keyset without rotating its key material. Destroy disables the keyset and removes it from Terraform state; it does not delete the keyset or its key material. Disabling can interrupt every client using the keyset, but leaves grants in place. Import the retained keyset ID to manage it again.\n\nGive each keyset one owner: Terraform or your provisioning automation, not both. Live Development API probes created, enabled and disabled an isolated test keyset. These probes do not establish the full Terraform lifecycle, including metadata updates; verify that lifecycle before production use. A live test keyset is a lasting resource: this provider can disable it but cannot delete it. See the README's live verification limits.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "Keyset ID as a UUID. Use this ID to import an existing keyset, including one retained after destroy.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required: true, Description: "Name of the keyset, from 1 to 64 ASCII letters, digits, underscores, slashes, or hyphens. Changing this value updates the existing keyset. CipherStash reserves `default` for the workspace's default keyset.",
				Validators: []validator.String{stringvalidator.LengthBetween(1, 64), stringvalidator.RegexMatches(regexp.MustCompile(`^[A-Za-z0-9_/-]+$`), "must contain only ASCII letters, digits, underscores, slashes or hyphens")},
			},
			"description": schema.StringAttribute{
				Required: true, Description: "Description of the keyset, from 1 to 256 characters. Changing this value updates the existing keyset.",
				Validators: []validator.String{stringvalidator.LengthBetween(1, 256)},
			},
			"enabled": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				Description: "Whether the keyset is enabled. Defaults to `true`. Set to `false` to disable access without deleting key material or grants. To keep an imported keyset disabled, set this to `false` in your configuration. A new keyset is created enabled, then disabled in a separate request if this is `false`. Metadata changes require an enabled keyset: a planned enable happens before metadata updates, and a planned disable happens afterward. Metadata changes to an already-disabled keyset require `enabled = true`; the provider never temporarily enables a keyset configured to remain disabled.",
			},
			"is_default": schema.BoolAttribute{
				Computed: true, Description: "Whether CipherStash identifies this as the workspace's default keyset. This value is computed; this resource cannot select the default keyset.",
			},
		},
	}
}

func (r *keysetResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}

	r.client = client
}

func (r *keysetResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		resp.Diagnostics.AddWarning("Destroy disables the keyset", "Applying this destroy will disable the keyset, interrupting clients that use it, then remove it from Terraform state. The keyset and key material remain remotely. Import its UUID to manage it again.")
		return
	}

	if req.State.Raw.IsNull() {
		return
	}

	var plan, current keysetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &current)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if current.Enabled.Equal(types.BoolValue(false)) && plan.Enabled.Equal(types.BoolValue(false)) &&
		((!plan.Name.IsUnknown() && !plan.Name.Equal(current.Name)) || (!plan.Description.IsUnknown() && !plan.Description.Equal(current.Description))) {
		resp.Diagnostics.AddError("Cannot modify disabled keyset", "CipherStash requires an enabled keyset to change its name or description. Set enabled = true to enable it before changing metadata. The provider will not temporarily enable a keyset configured to remain disabled.")
	}
}

func (r *keysetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan keysetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	created, err := r.client.CreateZeroKMSKeyset(ctx, control.CreateZeroKMSKeysetOptions{Name: plan.Name.ValueString(), Description: plan.Description.ValueString()})
	if err != nil {
		resp.Diagnostics.AddError("Cannot create keyset", operationError(err)+" A failed response can follow a completed write. Inspect inventory and import the keyset before retrying if it already exists.")
		return
	}
	defer created.Client.Wipe()

	current := keysetModelFrom(created.ZeroKMSKeyset)
	// Creation returns an identity before an optional disable or readback can
	// fail. Keep it so those failures do not orphan a non-deletable keyset.
	resp.Diagnostics.Append(resp.State.Set(ctx, current)...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(r.applyChanges(ctx, plan, current, &resp.State)...)
	}
}

func (r *keysetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state keysetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	found, err := r.findKeyset(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot read keyset", operationError(err))
		return
	}

	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, keysetModelFrom(*found))...)
}

func (r *keysetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, current keysetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &current)...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(r.applyChanges(ctx, plan, current, &resp.State)...)
	}
}

// Apply in-place changes both after creation and during Update. Persist each
// successful step before the next operation, then reconcile from inventory even
// on a write error. A failed operation is never silently retried or suppressed.
func (r *keysetResource) applyChanges(ctx context.Context, plan, current keysetModel, state *tfsdk.State) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	var opts control.ModifyZeroKMSKeysetOptions
	if !plan.Name.Equal(current.Name) {
		name := plan.Name.ValueString()
		opts.Name = &name
	}

	if !plan.Description.Equal(current.Description) {
		description := plan.Description.ValueString()
		opts.Description = &description
	}

	// Unknown configuration can defer this decision until apply.
	if !current.Enabled.ValueBool() && !plan.Enabled.ValueBool() && (opts.Name != nil || opts.Description != nil) {
		diagnostics.AddError("Cannot modify disabled keyset", "CipherStash requires an enabled keyset to change its name or description. Set enabled = true to enable it before changing metadata. The provider will not temporarily enable a keyset configured to remain disabled.")
		return diagnostics
	}

	// Metadata writes require an enabled keyset. Only enable when explicitly
	// planned, and retain that success even if the subsequent metadata write fails.
	if plan.Enabled.ValueBool() && !current.Enabled.ValueBool() {
		if err := r.client.EnableZeroKMSKeyset(ctx, current.ID.ValueString()); err != nil {
			diagnostics.AddError("Cannot change keyset enablement", operationError(err))
		} else {
			current.Enabled = plan.Enabled
			diagnostics.Append(state.Set(ctx, current)...)
		}
	}

	if !diagnostics.HasError() && (opts.Name != nil || opts.Description != nil) {
		if err := r.client.ModifyZeroKMSKeyset(ctx, current.ID.ValueString(), opts); err != nil {
			detail := operationError(err)
			if errors.Is(err, control.ErrForbidden) {
				detail = "CipherStash denied the metadata update. Check whether the keyset is disabled, as well as the Admin credential's permissions. Metadata changes require an enabled keyset."
			}

			diagnostics.AddError("Cannot modify keyset", detail)
		} else {
			current.Name, current.Description = plan.Name, plan.Description
			diagnostics.Append(state.Set(ctx, current)...)
		}
	}

	if !diagnostics.HasError() && !plan.Enabled.ValueBool() && current.Enabled.ValueBool() {
		if err := r.client.DisableZeroKMSKeyset(ctx, current.ID.ValueString()); err != nil {
			diagnostics.AddError("Cannot change keyset enablement", operationError(err))
		} else {
			current.Enabled = plan.Enabled
			diagnostics.Append(state.Set(ctx, current)...)
		}
	}

	found, err := r.findKeyset(ctx, current.ID.ValueString())
	if err != nil {
		diagnostics.AddError("Cannot confirm keyset changes", operationError(err)+" The keyset identity and last successful changes remain in state.")
		return diagnostics
	}

	if found == nil {
		diagnostics.AddError("Keyset not visible after write", "The keyset is absent from inventory after a write. Its identity remains in state; inspect inventory before retrying.")
		return diagnostics
	}

	observed := keysetModelFrom(*found)
	diagnostics.Append(state.Set(ctx, observed)...)
	if !diagnostics.HasError() && (!observed.Name.Equal(plan.Name) || !observed.Description.Equal(plan.Description) || !observed.Enabled.Equal(plan.Enabled)) {
		diagnostics.AddError("Keyset changes not visible", "Inventory does not match the requested metadata or enablement. The observed values are saved in state; inspect inventory before retrying.")
	}

	return diagnostics
}

func (r *keysetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state keysetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	found, err := r.findKeyset(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot inspect keyset before destroy", operationError(err))
		return
	}

	if found == nil {
		return
	}

	if !found.IsDisabled {
		if err := r.client.DisableZeroKMSKeyset(ctx, found.ID); err != nil {
			resp.Diagnostics.AddError("Cannot disable keyset for destroy", operationError(err)+" The resource remains in state.")
			return
		}

		found, err = r.findKeyset(ctx, found.ID)
		if err != nil {
			resp.Diagnostics.AddError("Cannot confirm keyset is disabled", operationError(err)+" The resource remains in state.")
			return
		}

		if found == nil {
			return
		}

		if !found.IsDisabled {
			resp.Diagnostics.AddError("Keyset remains enabled", "The disable request succeeded but inventory still reports the keyset enabled. The resource remains in state; inspect it before retrying.")
			return
		}
	}

	resp.Diagnostics.AddWarning("Disabled keyset retained remotely", "Keyset "+found.ID+" remains disabled in CipherStash. Its key material was not deleted. Terraform will forget this resource; import its UUID to manage it again.")
}

func (r *keysetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.ToLower(req.ID)
	if _, err := uuid.ParseUUID(id); err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Use the existing keyset UUID.")
		return
	}

	found, err := r.findKeyset(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Cannot import keyset", operationError(err))
		return
	}

	if found == nil {
		resp.Diagnostics.AddError("Keyset not found", "No keyset with this UUID exists in the configured workspace, including disabled keysets.")
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, keysetModelFrom(*found))...)
}

func (r *keysetResource) findKeyset(ctx context.Context, id string) (*control.ZeroKMSKeyset, error) {
	keysets, err := r.client.ListZeroKMSKeysets(ctx, control.ListZeroKMSKeysetsOptions{ShowDisabled: true})
	if err != nil {
		return nil, err
	}

	for _, keyset := range keysets {
		if keyset.ID == id {
			return &keyset, nil
		}
	}

	return nil, nil
}

func keysetModelFrom(keyset control.ZeroKMSKeyset) keysetModel {
	return keysetModel{
		ID: types.StringValue(keyset.ID), Name: types.StringValue(keyset.Name), Description: types.StringValue(keyset.Description),
		Enabled: types.BoolValue(!keyset.IsDisabled), IsDefault: types.BoolValue(keyset.IsDefault),
	}
}
