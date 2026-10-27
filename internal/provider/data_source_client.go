package provider

import (
	"context"

	"github.com/cipherstash/stack/languages/golang/control"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type clientDataSource struct {
	client controlClient
}

var _ datasource.DataSourceWithConfigure = &clientDataSource{}

func newClientDataSource() datasource.DataSource { return &clientDataSource{} }

type clientDataModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	KeysetIDs   types.Set    `tfsdk:"keyset_ids"`
}

func (d *clientDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_client"
}

func (d *clientDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Read an existing ZeroKMS client's name, description, and granted keyset IDs in the configured workspace. Use this data source when your application already has a client and you do not want Terraform to manage it.\n\nThis lookup does not import the client, change its grants, or recover its client key value. Removing the data source from your configuration does not delete the client. A missing client or failed lookup returns an error, not an empty result.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "ID of an existing ZeroKMS client in the configured workspace, as a UUID.",
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "Current name of the ZeroKMS client.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Current description of the ZeroKMS client.",
			},
			"keyset_ids": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "IDs of all keysets granted to the client, including disabled keysets. An empty set means the client has no grants. This lookup does not select a keyset or change any grants.",
			},
		},
	}
}

func (d *clientDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}

	d.client = client
}

func (d *clientDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data clientDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := uuid.ParseUUID(data.ID.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("id"), "Invalid client ID", "The client identifier must be a known UUID.")
		return
	}

	clients, err := d.client.ListClients(ctx, control.ListClientsOptions{})
	if err != nil {
		resp.Diagnostics.AddError("Cannot read client", operationError(err))
		return
	}

	for _, client := range clients {
		if client.ID != data.ID.ValueString() {
			continue
		}

		data.Name = types.StringValue(client.Name)
		data.Description = types.StringValue(client.Description)
		keysets, diagnostics := types.SetValueFrom(ctx, types.StringType, client.KeysetIDs)
		resp.Diagnostics.Append(diagnostics...)
		if resp.Diagnostics.HasError() {
			return
		}

		data.KeysetIDs = keysets
		resp.Diagnostics.Append(resp.State.Set(ctx, data)...)

		return
	}

	resp.Diagnostics.AddError("Client not found", "No client with this UUID exists in the configured workspace.")
}
