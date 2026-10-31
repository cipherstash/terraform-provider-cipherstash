package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	control "github.com/bndry-co/bndry/pkg/cipherstash/manage"
)

// actorResource is the machine identity resource. It is an actor rather than
// a bare access key because CTS lets an access-key principal create and delete
// actors (and the key each one owns) but refuses to delete bare access keys.
type actorResource struct {
	client controlClient
}

var (
	_ resource.ResourceWithConfigure   = &actorResource{}
	_ resource.ResourceWithImportState = &actorResource{}
)

func newActorResource() resource.Resource { return &actorResource{} }

type actorModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Kind        types.String `tfsdk:"kind"`
	Role        types.String `tfsdk:"role"`
	TokenExpiry types.Int64  `tfsdk:"token_expiry"`
	KeyID       types.String `tfsdk:"key_id"`
	AccessKey   types.String `tfsdk:"access_key"`
	CreatedAt   types.String `tfsdk:"created_at"`
}

func (r *actorResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cts_actor"
}

func (r *actorResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Create a machine identity and its access key in the configured workspace. An actor represents an application (`app`) or agent (`agent`); it is separate from a ZeroKMS client or a human workspace member.\n\nChanging any argument replaces the actor and creates a new access key. The CipherStash Token Service (CTS) does not support updating actors, and access-key credentials cannot edit access keys. Replacement is not a guarantee that the old credential or its issued tokens stop working immediately. Plan credential changes separately.\n\nThe access key is returned only when the actor is created. Terraform stores it in state and saved plans despite marking it sensitive. Import cannot recover the access key or token lifetime.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Actor ID, for example `app-JBSWY3DPEHPK3PXP`. Use this ID to import an existing actor.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "Name of the actor and its access key. Use a unique name within the workspace, from 1 to 41 characters. Changing this value replaces the actor.",
				Validators:    []validator.String{stringvalidator.LengthBetween(1, 41)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"kind": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Default:       stringdefault.StaticString("app"),
				Description:   "Type of machine identity: `app` or `agent`. Defaults to `app`. Changing this value replaces the actor.",
				Validators:    []validator.String{stringvalidator.OneOf("app", "agent")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"role": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Default:       stringdefault.StaticString("member"),
				Description:   "Access-key role: `admin`, `control`, or `member`. Defaults to `member`. Use Member for application cryptographic operations and Control for keyset and client-access automation; Control cannot derive data keys. Changing this value replaces the actor.",
				Validators:    []validator.String{stringvalidator.OneOf("admin", "control", "member")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"token_expiry": schema.Int64Attribute{
				Optional:      true,
				Description:   "Lifetime of tokens issued from the access key, in seconds, from 1 to 86400. When omitted, CTS uses 900 seconds. This does not set the access key's lifetime. CipherStash does not return this setting, so Terraform cannot detect changes made outside Terraform; it is null after import. Changing this value replaces the actor.",
				Validators:    []validator.Int64{int64validator.Between(1, 86400)},
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"key_id": schema.StringAttribute{
				Computed:      true,
				Description:   "16-character ID of the actor's access key. This is an identifier, not the secret access-key value.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"access_key": schema.StringAttribute{
				Computed:      true,
				Sensitive:     true,
				Description:   "Secret access-key value, beginning with `CSAK`. Returned only at creation and retained in Terraform state; null after import. Marking it sensitive does not remove it from state or saved plans.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{
				Computed:      true,
				Description:   "Creation time reported by CipherStash.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *actorResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}

	r.client = client
}

func (r *actorResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan actorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var expiry *int64
	if !plan.TokenExpiry.IsNull() {
		v := plan.TokenExpiry.ValueInt64()
		expiry = &v
	}

	created, err := r.client.CreateCTSActor(ctx, control.CreateCTSActorOptions{Name: plan.Name.ValueString(), Kind: control.CTSActorKind(plan.Kind.ValueString()), Role: control.CTSRole(plan.Role.ValueString()), TokenExpiry: expiry})
	if err != nil {
		resp.Diagnostics.AddError("Cannot create actor", operationError(err))
		return
	}
	defer created.Wipe()

	plan.ID = types.StringValue(created.ID)
	plan.KeyID = types.StringNull()
	plan.CreatedAt = types.StringValue(created.CreatedAt)
	plan.AccessKey = types.StringNull()
	secret, err := created.ExportAccessKey()
	if err == nil {
		plan.AccessKey = types.StringValue(string(secret))
	}

	clear(secret)
	// Persist the identity and one-time secret before any supplemental read.
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if err != nil {
		resp.Diagnostics.AddError("Cannot export actor access key", "The actor ID is saved in state, but its secret could not be exported. Replace the actor to obtain a new secret.")
		return
	}

	if resp.Diagnostics.HasError() {
		return
	}

	key, err := r.findAccessKey(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read actor after creation", "The actor ID and access key are saved in state. "+operationError(err))
		return
	}

	plan.KeyID = types.StringValue(key.ID)
	plan.CreatedAt = types.StringValue(key.CreatedAt)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *actorResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state actorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	actor, err := r.findActor(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot read actor", operationError(err))
		return
	}

	if actor == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.Name = types.StringValue(actor.Name)
	key, err := r.findAccessKey(ctx, state)
	if err != nil {
		// An actor without metadata still exists. Forgetting it would orphan it
		// and make the next create collide with its unique name.
		resp.Diagnostics.AddError("Cannot read actor's access key", "The actor still exists; state is retained. Its access-key metadata must match exactly one key. "+operationError(err))
		return
	}

	state.Name = types.StringValue(actor.Name)
	state.Kind = types.StringValue(string(actor.Kind))
	state.Role = types.StringValue(string(key.Role))
	state.KeyID = types.StringValue(key.ID)
	state.CreatedAt = types.StringValue(actor.CreatedAt)
	// access_key and token_expiry are not readable; keep whatever state has.
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update is never called: every argument requires replacement.
func (r *actorResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Actors cannot be updated in place", "This is a provider bug: all arguments are marked RequiresReplace.")
}

func (r *actorResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state actorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteCTSActor(ctx, state.ID.ValueString()); err != nil && !errors.Is(err, control.ErrNotFound) {
		resp.Diagnostics.AddError("Cannot delete actor", operationError(err))
	}
}

// ImportState imports by actor identifier. The secret stays null; replace
// the resource to obtain one.
func (r *actorResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *actorResource) findActor(ctx context.Context, id string) (*control.CTSActor, error) {
	seen := map[string]bool{}
	cursor := ""
	for {
		page, err := r.client.ListCTSActors(ctx, control.ListCTSActorsOptions{Limit: 100, Cursor: cursor})
		if err != nil {
			return nil, err
		}

		for _, actor := range page.Items {
			if actor.ID == id {
				return &actor, nil
			}
		}

		if page.NextCursor == "" {
			return nil, nil
		}

		if seen[page.NextCursor] {
			return nil, fmt.Errorf("actor pagination repeated a cursor")
		}

		seen[page.NextCursor] = true
		cursor = page.NextCursor
	}
}

func (r *actorResource) findAccessKey(ctx context.Context, state actorModel) (*control.CTSAccessKeyMetadata, error) {
	keys, err := r.client.ListCTSAccessKeys(ctx)
	if err != nil {
		return nil, err
	}

	var found *control.CTSAccessKeyMetadata
	for _, key := range keys {
		if (state.KeyID.IsNull() && key.Name == state.Name.ValueString()) || key.ID == state.KeyID.ValueString() {
			if found != nil {
				return nil, fmt.Errorf("ambiguous access-key metadata")
			}

			found = &key
		}
	}

	if found == nil {
		return nil, fmt.Errorf("missing access-key metadata")
	}

	return found, nil
}
