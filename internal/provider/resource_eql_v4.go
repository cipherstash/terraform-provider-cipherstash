package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/eql"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type eqlResource struct {
	database eqlDatabase
}

var (
	_ resource.ResourceWithConfigure   = &eqlResource{}
	_ resource.ResourceWithImportState = &eqlResource{}
	_ resource.ResourceWithModifyPlan  = &eqlResource{}
)

func newEQLResource() resource.Resource { return &eqlResource{} }

type eqlModel struct {
	ID             types.String `tfsdk:"id"`
	Database       types.String `tfsdk:"database"`
	Version        types.String `tfsdk:"version"`
	RequireORE     types.Bool   `tfsdk:"require_ore"`
	Schema         types.String `tfsdk:"schema"`
	InternalSchema types.String `tfsdk:"internal_schema"`
	SHA256         types.String `tfsdk:"sha256"`
	OREAvailable   types.Bool   `tfsdk:"ore_available"`
	Owner          types.String `tfsdk:"owner"`
	PgcryptoSchema types.String `tfsdk:"pgcrypto_schema"`
}

const uninstallGuidance = "This provider does not uninstall EQL: uninstalling would break every column typed with an EQL domain, and the domains in schema public would remain. To stop managing the installation without changing the database, replace the resource with a removed block that sets lifecycle { destroy = false }, or run terraform state rm."

func (r *eqlResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_eql_v4"
}

func (r *eqlResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Install CipherStash EQL v4, the PostgreSQL types and functions that store, compare and index encrypted values, into one database. The provider's `database` settings choose the server and role; the role that installs EQL owns every EQL object.\n\nThe provider contains the installer for each supported version: the `eql-v4-install.sql` asset of the matching cipherstash/stack Go release, checked against its SHA-256. Create runs it in one transaction with `search_path = public`, under the same advisory lock as the `stash` CLI's installer. It refuses, changing nothing, if the database already has an `eql_v4` or `eql_v4_internal` schema (import it instead), if `pgcrypto` is installed in a schema other than `public` or `extensions`, or if the role lacks `CREATE` on the database or on `public`. After the installer runs, it rolls back unless `eql_v4.version()` matches and, when `require_ore` is true, the ORE operator class exists.\n\nInstall `pgcrypto` before EQL, for example with a `postgresql_extension` resource that this resource depends on. Otherwise the installer creates it in a new `extensions` schema, and every role that compares ORE-encrypted values also needs `USAGE` on that schema.\n\nEQL issues no grants. Roles that query encrypted columns need `USAGE` on both `schema` and `internal_schema`; grant it with another provider, such as `postgresql_grant`, referencing these attributes so Terraform installs EQL first.\n\nThe provider cannot upgrade EQL yet: changing `version` is rejected. The installer drops and re-creates both schemas, removing every grant and every index built on EQL functions. To upgrade by hand, remove the resource from state, run the new version's installer, import the installation with the new `version`, then restore grants and re-create indexes; the README describes each step. Destroy does not uninstall EQL; it fails while EQL is installed and succeeds once it is gone.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "The database name. Use the database name to import an existing installation.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"database": schema.StringAttribute{
				Required:      true,
				Description:   "Name of the database to install EQL into, on the server from the provider's `database` settings. Changing this value replaces the resource. Because destroy refuses while EQL is installed, remove the old installation from state first.",
				Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"version": schema.StringAttribute{
				Required:    true,
				Description: "EQL version to install, as `eql_v4.version()` reports it, such as `go-0.1.0-rc.3` for the installer released with cipherstash/stack Go v0.1.0-rc.3. It must be a version compiled into this provider: " + strings.Join(eql.Versions(), ", ") + ". Refresh reads the installed version, so an installation changed outside Terraform shows as a difference. Changing it is rejected.",
				Validators:  []validator.String{stringvalidator.OneOf(eql.Versions()...)},
			},
			"require_ore": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Whether Create rolls back when the installer cannot create the ORE operator class, which needs a superuser or Amazon RDS `rds_superuser`. Without it the installer disables the 20 ORE-backed domains and still succeeds. Defaults to `true`. Changing it only updates state.",
			},
			"schema": schema.StringAttribute{
				Computed:    true,
				Default:     stringdefault.StaticString(eql.Schema),
				Description: "The EQL schema, `eql_v4`. Reference it in grants so Terraform installs EQL before granting on it.",
			},
			"internal_schema": schema.StringAttribute{
				Computed:    true,
				Default:     stringdefault.StaticString(eql.InternalSchema),
				Description: "The schema of EQL's internal functions, `eql_v4_internal`. Roles that query encrypted columns need `USAGE` on it as well, because EQL functions run with the caller's privileges.",
			},
			"sha256": schema.StringAttribute{
				Computed:    true,
				Description: "SHA-256 of the installer for `version`, matching the release asset. Null after refresh finds a version this provider has no installer for.",
			},
			"ore_available": schema.BoolAttribute{
				Computed:      true,
				Description:   "Whether the ORE operator class exists and no ORE domain is disabled.",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"owner": schema.StringAttribute{
				Computed:      true,
				Description:   "Role that owns schema `eql_v4`: the role that installed EQL.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"pgcrypto_schema": schema.StringAttribute{
				Computed:      true,
				Description:   "Schema of the `pgcrypto` extension, which EQL's ORE comparisons call. Null when `pgcrypto` is not installed.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *eqlResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	database, err := databaseFromProviderData(req.ProviderData)
	if err != nil {
		providerDataError(&resp.Diagnostics, err)
		return
	}

	r.database = database
}

func (r *eqlResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan eqlModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || plan.Version.IsUnknown() {
		return
	}

	if !req.State.Raw.IsNull() {
		var state eqlModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}

		if !plan.Version.Equal(state.Version) {
			resp.Diagnostics.AddAttributeError(path.Root("version"), "EQL upgrades are not supported", "The database has EQL "+state.Version.ValueString()+" and the configuration asks for "+plan.Version.ValueString()+". This provider cannot upgrade EQL yet: the installer drops and re-creates both EQL schemas, removing every grant and every index built on EQL functions. Set version to the installed version, or upgrade by hand as the README describes.")
			return
		}
	}

	if digest, ok := eql.SHA256(plan.Version.ValueString()); ok {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("sha256"), digest)...)
	}
}

func (r *eqlResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan eqlModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	database := plan.Database.ValueString()
	installErr := r.database.InstallEQL(ctx, database, plan.Version.ValueString(), plan.RequireORE.ValueBool())
	switch {
	case eql.Refused(installErr):
		resp.Diagnostics.AddError("EQL installation refused", refusal(installErr))
		return
	case installErr != nil && !errors.Is(installErr, eql.ErrCommitUnknown):
		resp.Diagnostics.AddError("Cannot install EQL", databaseError(installErr)+" The transaction rolled back, so the database is unchanged.")
		return
	}

	// The transaction committed, or COMMIT failed without a reply. Keep the
	// identity before readback so a failed read cannot orphan an installation.
	plan.ID = plan.Database
	plan.OREAvailable, plan.Owner, plan.PgcryptoSchema = types.BoolNull(), types.StringNull(), types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)

	installation, readErr := r.database.InspectEQL(ctx, database)
	switch {
	case readErr != nil && installErr != nil:
		resp.Diagnostics.AddError("Cannot confirm EQL installation", "The connection failed while committing the installation, and reading the database afterwards also failed: "+databaseError(readErr)+" The installation is retained in state; inspect the database before the next apply.")
	case readErr != nil:
		resp.Diagnostics.AddError("Cannot confirm EQL installation", databaseError(readErr)+" The installation committed and is retained in state.")
	case !installation.Installed && installErr != nil:
		resp.State.RemoveResource(ctx)
		resp.Diagnostics.AddError("Cannot install EQL", "The connection failed while committing the installation, and the database has no EQL installation, so it did not commit. Retry the apply.")
	case !installation.Installed:
		resp.Diagnostics.AddError("EQL installation not visible", "The installation committed but a fresh connection does not see it. It is retained in state; inspect the database before the next apply.")
	case installation.Version != plan.Version.ValueString():
		resp.Diagnostics.AddError("Unexpected EQL version", "The database reports EQL "+installation.Version+" instead of "+plan.Version.ValueString()+". It is retained in state; inspect the database before the next apply.")
	default:
		if installErr != nil {
			resp.Diagnostics.AddWarning("EQL installation confirmed after a commit error", "The connection failed while committing the installation, but a fresh connection confirms EQL "+installation.Version+" is installed.")
		}

		resp.Diagnostics.Append(resp.State.Set(ctx, applyInstallation(plan, installation))...)
	}
}

func (r *eqlResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state eqlModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	installation, err := r.database.InspectEQL(ctx, state.Database.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot read EQL installation", databaseError(err))
		return
	}

	if !installation.Installed {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, applyInstallation(state, installation))...)
}

func (r *eqlResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state eqlModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.Version.Equal(state.Version) {
		resp.Diagnostics.AddError("EQL cannot be upgraded in place", "This is a provider bug: planning rejects version changes.")
		return
	}

	// Only require_ore can change, and it governs Create alone.
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *eqlResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state eqlModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	installation, err := r.database.InspectEQL(ctx, state.Database.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot inspect EQL installation", databaseError(err)+" State is retained because the installation's absence could not be confirmed.")
		return
	}

	if installation.Installed {
		resp.Diagnostics.AddError("EQL is still installed", uninstallGuidance)
	}
}

func (r *eqlResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use the name of the database EQL is installed in.")
		return
	}

	installation, err := r.database.InspectEQL(ctx, req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Cannot import EQL installation", databaseError(err))
		return
	}

	if !installation.Installed {
		resp.Diagnostics.AddError("EQL is not installed", "The database "+req.ID+" has no EQL v4 installation. Import does not install EQL.")
		return
	}

	state := eqlModel{
		ID:             types.StringValue(req.ID),
		Database:       types.StringValue(req.ID),
		RequireORE:     types.BoolValue(true),
		Schema:         types.StringValue(eql.Schema),
		InternalSchema: types.StringValue(eql.InternalSchema),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, applyInstallation(state, installation))...)
}

// applyInstallation copies what the database reports into the model.
func applyInstallation(model eqlModel, installation eql.Installation) eqlModel {
	model.Version = types.StringValue(installation.Version)
	model.SHA256 = types.StringNull()
	if digest, ok := eql.SHA256(installation.Version); ok {
		model.SHA256 = types.StringValue(digest)
	}

	model.OREAvailable = types.BoolValue(installation.OREAvailable)
	model.Owner = types.StringValue(installation.Owner)
	model.PgcryptoSchema = types.StringNull()
	if installation.PgcryptoSchema != "" {
		model.PgcryptoSchema = types.StringValue(installation.PgcryptoSchema)
	}

	return model
}

// refusal explains an eql.Refused error. Each one changed nothing.
func refusal(err error) string {
	switch {
	case errors.Is(err, eql.ErrAlreadyInstalled):
		return "The database already has an eql_v4 or eql_v4_internal schema. Import the existing installation with its database name instead; installing again would drop both schemas and every grant and index that depends on them."
	case errors.Is(err, eql.ErrLocked):
		return "Another EQL installation, from this provider or the stash CLI, holds the lifecycle lock on this database. Retry when it has finished."
	case errors.Is(err, eql.ErrPgcryptoSchema):
		return "The pgcrypto extension is installed in a schema other than public or extensions, where EQL cannot find it. Move it with ALTER EXTENSION pgcrypto SET SCHEMA public, then retry."
	case errors.Is(err, eql.ErrPrivilege):
		return "The database role lacks CREATE on the database or on schema public, which the installer needs."
	case errors.Is(err, eql.ErrOREUnavailable):
		return "The installer could not create the ORE operator class, which needs a superuser or Amazon RDS rds_superuser, so the installation rolled back. Connect as such a role, or set require_ore = false to install with the ORE-backed domains disabled."
	case errors.Is(err, eql.ErrVersionMismatch):
		return "After running the installer, the database did not report the expected EQL version, so the installation rolled back. This is a provider bug."
	default:
		return "No installer for this version is compiled into the provider. This is a provider bug: planning validates the version."
	}
}
