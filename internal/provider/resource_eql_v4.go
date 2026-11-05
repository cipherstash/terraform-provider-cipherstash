package provider

import (
	"context"
	"errors"
	"slices"
	"strconv"
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
	AllowRebuild   types.Bool   `tfsdk:"allow_index_rebuild"`
	Schema         types.String `tfsdk:"schema"`
	InternalSchema types.String `tfsdk:"internal_schema"`
	SHA256         types.String `tfsdk:"sha256"`
	OREAvailable   types.Bool   `tfsdk:"ore_available"`
	Owner          types.String `tfsdk:"owner"`
	PgcryptoSchema types.String `tfsdk:"pgcrypto_schema"`
}

func (r *eqlResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_eql_v4"
}

func (r *eqlResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Install CipherStash EQL v4, the PostgreSQL types and functions that store, compare and index encrypted values, into one database. The provider's `database` settings choose the server and role; the role that installs EQL owns every EQL object.\n\nThe provider contains the installer for each supported version: the `eql-v4-install.sql` asset of the matching cipherstash/stack Go release, checked against its SHA-256. Create runs it in one transaction with `search_path = public`, under the same advisory lock as the `stash` CLI's installer. It refuses, changing nothing, if the database already has an `eql_v4` or `eql_v4_internal` schema (import it instead), if `pgcrypto` is installed in a schema other than `public` or `extensions`, or if the role lacks `CREATE` on the database or on `public`. After the installer runs, it rolls back unless `eql_v4.version()` matches and, when `require_ore` is true, the ORE operator class exists.\n\nInstall `pgcrypto` before EQL, for example with a `postgresql_extension` resource that this resource depends on. Otherwise the installer creates it in a new `extensions` schema, and every role that compares ORE-encrypted values also needs `USAGE` on that schema.\n\nEQL issues no grants. Roles that query encrypted columns need `USAGE` on both `schema` and `internal_schema`; grant it with another provider, such as `postgresql_grant`, referencing these attributes so Terraform installs EQL first.\n\nChanging `version` to a later release upgrades EQL in one transaction under the same lock. The new installer drops and re-creates both schemas, and the provider restores what that removes: the grants on both schemas and their routines and types, the default privileges in them and, when `allow_index_rebuild` is true, the indexes that call EQL functions, with their comments and `CLUSTER` marks. It refuses, changing nothing, to move to an earlier release; while any other object outside EQL depends on EQL, such as a view, policy or constraint that calls an EQL function, or an index on a partitioned table, a materialized view or another session's temporary table, in a non-default tablespace or with a statistics target; while indexes need rebuilding and `allow_index_rebuild` is false; or if the role lacks the privileges of the owner of the EQL objects, of the tables whose indexes it rebuilds, or of the roles whose default privileges it restores. Tables whose indexes it rebuilds are locked until the upgrade commits. Routines and types that are new in the release get what the restored default privileges grant, as if they had been created after them. Restored grants record the database role as grantor. To upgrade from a version this provider does not ship, upgrade by hand as the README describes.\n\nDestroy uninstalls EQL in one transaction under the same lock. It refuses, changing nothing, while any column uses a `public.eql_v4_*` domain, while any object outside EQL depends on it (such as an index or view that calls an EQL function), if the role lacks the privileges of the owner of the EQL schemas or of the domains and functions EQL adds to `public`, or if the provider has no uninstaller for the version the database reports, which planning already rejects, before Terraform destroys anything else. Otherwise it runs that release's `eql-v4-uninstall.sql`, which drops both schemas, then drops the domains and functions it leaves in `public`, without CASCADE. `pgcrypto` and the `extensions` schema stay. To stop managing the installation without changing the database, use a `removed` block that sets `lifecycle { destroy = false }`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "The database name. Use the database name to import an existing installation.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"database": schema.StringAttribute{
				Required:      true,
				Description:   "Name of the database to install EQL into, on the server from the provider's `database` settings. Changing this value replaces the resource: destroy uninstalls EQL from the old database, under the same refusals as any destroy, and create installs it in the new one.",
				Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"version": schema.StringAttribute{
				Required:    true,
				Description: "EQL version to install, as `eql_v4.version()` reports it, such as `go-0.1.0-rc.3` for the installer released with cipherstash/stack Go v0.1.0-rc.3. It must be a version compiled into this provider: " + strings.Join(eql.Versions(), ", ") + ". Refresh reads the installed version, so an installation changed outside Terraform shows as a difference. Changing it to a later version upgrades EQL; changing it to an earlier one is rejected.",
				Validators:  []validator.String{stringvalidator.OneOf(eql.Versions()...)},
			},
			"require_ore": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Whether Create rolls back when the installer cannot create the ORE operator class, which needs a superuser or Amazon RDS `rds_superuser`. Without it the installer disables the 20 ORE-backed domains and still succeeds. Defaults to `true`. Changing it only updates state.",
			},
			"allow_index_rebuild": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether an upgrade may drop and rebuild the indexes that call EQL functions, which the installer drops. While false, an upgrade refuses when such indexes exist. Defaults to `false`. Changing it only updates state.",
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
	var plan, state eqlModel
	if !req.Plan.Raw.IsNull() {
		resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	}

	if !req.State.Raw.IsNull() {
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Destroy, including the destroy half of a replacement, uninstalls the
	// version in state, which refresh has just read from the database. Refuse
	// now rather than after Terraform has destroyed the resources that depend
	// on this one. Delete checks the database again.
	if !req.State.Raw.IsNull() && (req.Plan.Raw.IsNull() || !plan.Database.Equal(state.Database)) && !eql.Uninstallable(state.Version.ValueString()) {
		resp.Diagnostics.AddError("EQL uninstall refused", noUninstaller(state.Version.ValueString()))
		return
	}

	if req.Plan.Raw.IsNull() || plan.Version.IsUnknown() {
		return
	}

	// A replacement installs afresh, so only an in-place change is an upgrade.
	if !req.State.Raw.IsNull() && plan.Database.Equal(state.Database) && !plan.Version.Equal(state.Version) {
		from, to := state.Version.ValueString(), plan.Version.ValueString()
		switch {
		case !slices.Contains(eql.Versions(), from):
			resp.Diagnostics.AddAttributeError(path.Root("version"), "Cannot upgrade EQL", "The database has EQL "+from+", which this provider does not ship, so it cannot upgrade from it. Upgrade by hand as the README describes.")
			return
		case !eql.Later(from, to):
			resp.Diagnostics.AddAttributeError(path.Root("version"), "EQL downgrades are not supported", "The database has EQL "+from+", which was released after "+to+". Set version to "+from+" or a later version.")
			return
		}

		resp.Diagnostics.AddAttributeWarning(path.Root("version"), "EQL upgrade reinstalls EQL", "Applying this plan upgrades EQL from "+from+" to "+to+" in one transaction. The installer drops and re-creates both EQL schemas; the provider restores their grants and default privileges, and rebuilds the indexes that call EQL functions when allow_index_rebuild is true. Tables with such indexes are locked until the upgrade commits. The upgrade refuses, changing nothing, if other objects depend on EQL.")
		// The reinstall can change what the database reports: the installing
		// role owns the new schemas, and the ORE operator class depends on its
		// privileges.
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("owner"), types.StringUnknown())...)
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("ore_available"), types.BoolUnknown())...)
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("pgcrypto_schema"), types.StringUnknown())...)
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

	if plan.Version.Equal(state.Version) {
		// Only require_ore and allow_index_rebuild changed; they govern Create
		// and upgrades alone.
		resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
		return
	}

	// The response state starts as the prior state, so a failure that sets no
	// state keeps the previous version.
	database, from, to := state.Database.ValueString(), state.Version.ValueString(), plan.Version.ValueString()
	report, upgradeErr := r.database.UpgradeEQL(ctx, database, from, to, plan.RequireORE.ValueBool(), plan.AllowRebuild.ValueBool())
	switch {
	case eql.Refused(upgradeErr):
		resp.Diagnostics.AddError("EQL upgrade refused", refusal(upgradeErr))

		return
	case upgradeErr != nil && !errors.Is(upgradeErr, eql.ErrCommitUnknown):
		resp.Diagnostics.AddError("Cannot upgrade EQL", databaseError(upgradeErr)+" The transaction rolled back, so the database is unchanged.")

		return
	}

	// The transaction committed, or COMMIT failed without a reply.
	installation, readErr := r.database.InspectEQL(ctx, database)
	switch {
	case readErr != nil && upgradeErr != nil:
		resp.Diagnostics.AddError("Cannot confirm EQL upgrade", "The connection failed while committing the upgrade, and reading the database afterwards also failed: "+databaseError(readErr)+" The previous version is retained in state; inspect the database before the next apply.")
	case readErr != nil:
		plan.OREAvailable, plan.Owner, plan.PgcryptoSchema = types.BoolNull(), types.StringNull(), types.StringNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
		resp.Diagnostics.AddError("Cannot confirm EQL upgrade", databaseError(readErr)+" The upgrade committed and the new version is saved in state.")
	case upgradeErr != nil && installation.Installed && installation.Version == from:
		resp.Diagnostics.AddError("Cannot upgrade EQL", "The connection failed while committing the upgrade, and the database still has EQL "+from+", so it did not commit. Retry the apply.")
	case !installation.Installed:
		resp.Diagnostics.AddError("EQL upgrade not visible", "After the upgrade, a fresh connection finds no EQL installation. The previous version is retained in state; inspect the database before the next apply.")
	case installation.Version != to:
		resp.Diagnostics.Append(resp.State.Set(ctx, applyInstallation(plan, installation))...)
		resp.Diagnostics.AddError("Unexpected EQL version", "The database reports EQL "+installation.Version+" instead of "+to+"; inspect the database before the next apply.")
	default:
		if upgradeErr != nil {
			resp.Diagnostics.AddWarning("EQL upgrade confirmed after a commit error", "The connection failed while committing the upgrade, but a fresh connection confirms EQL "+to+" is installed.")
		}

		if len(report.RebuiltIndexes) > 0 {
			resp.Diagnostics.AddWarning("EQL upgrade rebuilt indexes", "The upgrade dropped and rebuilt these indexes, which call EQL functions: "+strings.Join(report.RebuiltIndexes, ", ")+".")
		}

		if len(report.RemovedObjects) > 0 {
			resp.Diagnostics.AddWarning("EQL upgrade did not restore some grants", "EQL "+to+" no longer has these routines and types, so their grants were not restored: "+strings.Join(report.RemovedObjects, ", ")+".")
		}

		resp.Diagnostics.Append(resp.State.Set(ctx, applyInstallation(plan, installation))...)
	}
}

func (r *eqlResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state eqlModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	database := state.Database.ValueString()
	uninstallErr := r.database.UninstallEQL(ctx, database)
	switch {
	case uninstallErr == nil:
		return
	case errors.Is(uninstallErr, eql.ErrNoUninstaller):
		// Planning checked the version in state, so EQL changed since.
		resp.Diagnostics.AddError("EQL uninstall refused", "EQL in the database changed after planning from "+state.Version.ValueString()+" to a version this provider has no uninstaller for; it ships those for "+strings.Join(eql.Versions(), ", ")+". Refresh and review the plan.")
		return
	case eql.Refused(uninstallErr):
		resp.Diagnostics.AddError("EQL uninstall refused", refusal(uninstallErr))
		return
	case !errors.Is(uninstallErr, eql.ErrCommitUnknown):
		resp.Diagnostics.AddError("Cannot uninstall EQL", databaseError(uninstallErr)+" The transaction rolled back, so the database is unchanged.")
		return
	}

	installation, readErr := r.database.InspectEQL(ctx, database)
	switch {
	case readErr != nil:
		resp.Diagnostics.AddError("Cannot confirm EQL uninstall", "The connection failed while committing the uninstall, and reading the database afterwards also failed: "+databaseError(readErr)+" The installation is retained in state; inspect the database before the next apply.")
	case installation.Installed:
		resp.Diagnostics.AddError("Cannot uninstall EQL", "The connection failed while committing the uninstall, and EQL is still installed, so it did not commit. Retry the apply.")
	default:
		resp.Diagnostics.AddWarning("EQL uninstall confirmed after a commit error", "The connection failed while committing the uninstall, but a fresh connection confirms EQL is no longer installed.")
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
		AllowRebuild:   types.BoolValue(false),
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

// noUninstaller explains why the provider cannot uninstall EQL version.
func noUninstaller(version string) string {
	return "The database reports EQL " + version + ", and this provider has no uninstaller for it; it ships those for " + strings.Join(eql.Versions(), ", ") + ". Uninstall with a provider version that has it, or stop managing the installation without changing the database with a removed block that sets lifecycle { destroy = false }."
}

// refusal explains an eql.Refused error. Each one changed nothing.
func refusal(err error) string {
	named := ""
	if objects, ok := errors.AsType[*eql.ObjectsError](err); ok {
		named = strings.Join(objects.Names, ", ")
		if more := objects.Total - len(objects.Names); more > 0 {
			named += " and " + strconv.Itoa(more) + " more"
		}
	}

	switch {
	case errors.Is(err, eql.ErrAlreadyInstalled):
		return "The database already has an eql_v4 or eql_v4_internal schema. Import the existing installation with its database name instead; installing again would drop both schemas and every grant and index that depends on them."
	case errors.Is(err, eql.ErrLocked):
		return "Another EQL installation or uninstall, from this provider or the stash CLI, holds the lifecycle lock on this database. Retry when it has finished."
	case errors.Is(err, eql.ErrPgcryptoSchema):
		return "The pgcrypto extension is installed in a schema other than public or extensions, where EQL cannot find it. Move it with ALTER EXTENSION pgcrypto SET SCHEMA public, then retry."
	case errors.Is(err, eql.ErrPrivilege):
		return "The database role lacks CREATE on the database or on schema public, which the installer needs."
	case errors.Is(err, eql.ErrOREUnavailable):
		return "The installer could not create the ORE operator class, which needs a superuser or Amazon RDS rds_superuser, so the installation rolled back. Connect as such a role, or set require_ore = false to install with the ORE-backed domains disabled."
	case errors.Is(err, eql.ErrVersionMismatch):
		return "After running the installer, the database did not report the expected EQL version, so the installation rolled back. This is a provider bug."
	case errors.Is(err, eql.ErrNotOwner):
		return "The database role lacks the privileges of the owner of these objects, which the upgrade or uninstall changes: " + named + ". Connect as their owner or a member of it."
	case errors.Is(err, eql.ErrInUse):
		return "These columns use EQL domains: " + named + ". Without EQL they would reject writes or compare whole ciphertexts. Drop them or convert them to other types, then retry."
	case errors.Is(err, eql.ErrDependents):
		return "Reinstalling or uninstalling EQL drops both EQL schemas with CASCADE, which would drop these objects that depend on it: " + named + ". Remove them, then retry; after an upgrade, re-create them."
	case errors.Is(err, eql.ErrIndexesNeedRebuild):
		return "The installer would drop these indexes, which call EQL functions: " + named + ". Set allow_index_rebuild = true to rebuild them during the upgrade. Tables with these indexes are locked until the upgrade commits."
	case errors.Is(err, eql.ErrIndexMismatch):
		return "After the installer ran, these rebuilt indexes differed from the originals, for example in their operator classes, so the upgrade rolled back: " + named + ". The release may have changed the functions they call; rebuild them by hand after upgrading as the README describes."
	case errors.Is(err, eql.ErrDowngrade):
		return "The target version is not later than the installed version. This is a provider bug: planning rejects downgrades."
	case errors.Is(err, eql.ErrNotInstalledVersion):
		return "The database no longer has the EQL version in state, so EQL changed after planning. Refresh and review the plan."
	case errors.Is(err, eql.ErrUninstallIncomplete):
		return "After running the uninstaller, EQL objects remained in the database, so the uninstall rolled back. This is a provider bug."
	default:
		return "No installer for this version is compiled into the provider. This is a provider bug: planning validates the version."
	}
}
