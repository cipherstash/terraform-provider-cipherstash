package provider

import (
	"context"
	"errors"
	"fmt"
	"testing"

	control "github.com/bndry-co/bndry/pkg/cipherstash/manage"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"
)

const (
	clientID       = "11111111-1111-4111-8111-111111111111"
	keysetID       = "22222222-2222-4222-8222-222222222222"
	tenantKeysetID = "33333333-3333-4333-8333-333333333333"
)

// Unimplemented operations panic via the embedded interface: an unexpected
// mutation during refresh/import must fail, not silently succeed.
type testControl struct {
	controlClient
	actors        func(control.ListCTSActorsOptions) (control.CTSActorPage, error)
	keys          func() ([]control.CTSAccessKeyMetadata, error)
	clients       func() ([]control.ZeroKMSClient, error)
	deleteActor   func(string) error
	deleteClient  func(string) error
	grant         func(string, string) error
	revoke        func(string, string) error
	createKeyset  func(control.CreateZeroKMSKeysetOptions) (*control.CreatedZeroKMSKeyset, error)
	keysets       func(control.ListZeroKMSKeysetsOptions) ([]control.ZeroKMSKeyset, error)
	modifyKeyset  func(string, control.ModifyZeroKMSKeysetOptions) error
	enableKeyset  func(string) error
	disableKeyset func(string) error
}

func (c testControl) ListCTSActors(_ context.Context, opts control.ListCTSActorsOptions) (control.CTSActorPage, error) {
	return c.actors(opts)
}

func (c testControl) ListCTSAccessKeys(context.Context) ([]control.CTSAccessKeyMetadata, error) {
	return c.keys()
}

func (c testControl) ListZeroKMSClients(context.Context, control.ListZeroKMSClientsOptions) ([]control.ZeroKMSClient, error) {
	return c.clients()
}
func (c testControl) DeleteCTSActor(_ context.Context, id string) error { return c.deleteActor(id) }
func (c testControl) DeleteZeroKMSClient(_ context.Context, id string) error {
	return c.deleteClient(id)
}
func (c testControl) GrantZeroKMSKeyset(_ context.Context, keysetID, clientID string) error {
	return c.grant(keysetID, clientID)
}

func (c testControl) RevokeZeroKMSKeyset(_ context.Context, keysetID, clientID string) error {
	return c.revoke(keysetID, clientID)
}

func (c testControl) CreateZeroKMSKeyset(_ context.Context, opts control.CreateZeroKMSKeysetOptions) (*control.CreatedZeroKMSKeyset, error) {
	return c.createKeyset(opts)
}

func (c testControl) ListZeroKMSKeysets(_ context.Context, opts control.ListZeroKMSKeysetsOptions) ([]control.ZeroKMSKeyset, error) {
	return c.keysets(opts)
}

func (c testControl) ModifyZeroKMSKeyset(_ context.Context, id string, opts control.ModifyZeroKMSKeysetOptions) error {
	return c.modifyKeyset(id, opts)
}
func (c testControl) EnableZeroKMSKeyset(_ context.Context, id string) error {
	return c.enableKeyset(id)
}
func (c testControl) DisableZeroKMSKeyset(_ context.Context, id string) error {
	return c.disableKeyset(id)
}

func resourceState(t *testing.T, r resource.Resource, model any) tfsdk.State {
	t.Helper()
	var schema resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schema)
	noErrors(t, schema.Diagnostics)
	state := tfsdk.State{Schema: schema.Schema}
	noErrors(t, state.Set(context.Background(), model))

	return state
}

func noErrors(t *testing.T, diagnostics diag.Diagnostics) {
	t.Helper()
	require.False(t, diagnostics.HasError(), "unexpected diagnostics: %v", diagnostics)
}

func savedActor() actorModel {
	return actorModel{
		ID: types.StringValue("app-actor"), Name: types.StringValue("before"), Kind: types.StringValue("app"), Role: types.StringValue("member"),
		TokenExpiry: types.Int64Value(1234), KeyID: types.StringValue("key-1"), AccessKey: types.StringValue("test-secret-not-a-credential"), CreatedAt: types.StringValue("before"),
	}
}

func savedClient() clientModel {
	return clientModel{
		ID: types.StringValue(clientID), Name: types.StringValue("before"), Description: types.StringValue("old description"),
		KeysetID: types.StringValue(keysetID), ClientKey: types.StringValue("test-secret-not-a-credential"),
	}
}

func TestActorRefreshPaginationAndSecrets(t *testing.T) {
	r := &actorResource{client: testControl{
		actors: func(opts control.ListCTSActorsOptions) (control.CTSActorPage, error) {
			switch opts.Cursor {
			case "":
				return control.CTSActorPage{Items: []control.CTSActor{{ID: "app-unrelated", Name: "unrelated"}}, NextCursor: "page2"}, nil
			case "page2":
				return control.CTSActorPage{Items: []control.CTSActor{{ID: "app-actor", Name: "renamed", Kind: "agent", CreatedAt: "2026-10-26T00:00:00Z"}}}, nil
			default:
				require.FailNowf(t, "unexpected cursor", "%q", opts.Cursor)
				return control.CTSActorPage{}, nil
			}
		},
		keys: func() ([]control.CTSAccessKeyMetadata, error) {
			return []control.CTSAccessKeyMetadata{{ID: "other-key", Name: "renamed", Role: "member"}, {ID: "key-1", Name: "renamed", Role: "control"}}, nil
		},
	}}
	before := savedActor()
	state := resourceState(t, r, before)
	resp := resource.ReadResponse{State: state}
	r.Read(context.Background(), resource.ReadRequest{State: state}, &resp)
	noErrors(t, resp.Diagnostics)
	var after actorModel
	noErrors(t, resp.State.Get(context.Background(), &after))
	require.Equal(t, "renamed", after.Name.ValueString())
	require.Equal(t, "agent", after.Kind.ValueString())
	require.Equal(t, "control", after.Role.ValueString())
	require.Equal(t, "2026-10-26T00:00:00Z", after.CreatedAt.ValueString())
	require.True(t, after.AccessKey.Equal(before.AccessKey), "refresh lost access key")
	require.True(t, after.TokenExpiry.Equal(before.TokenExpiry), "refresh lost token expiry")
}

func TestActorRefreshMissingAndFailedReads(t *testing.T) {
	for _, scenario := range []string{"absent", "listing failure", "missing key", "key failure", "cursor cycle"} {
		t.Run(scenario, func(t *testing.T) {
			r := &actorResource{client: testControl{
				actors: func(control.ListCTSActorsOptions) (control.CTSActorPage, error) {
					switch scenario {
					case "absent":
						return control.CTSActorPage{}, nil
					case "listing failure":
						return control.CTSActorPage{}, control.ErrForbidden
					case "cursor cycle":
						return control.CTSActorPage{NextCursor: "repeat"}, nil
					default:
						return control.CTSActorPage{Items: []control.CTSActor{{ID: "app-actor", Name: "before"}}}, nil
					}
				},
				keys: func() ([]control.CTSAccessKeyMetadata, error) {
					if scenario == "key failure" {
						return nil, errors.New("upstream body test-secret-not-a-credential")
					}

					return nil, nil
				},
			}}
			state := resourceState(t, r, savedActor())
			resp := resource.ReadResponse{State: state}
			r.Read(context.Background(), resource.ReadRequest{State: state}, &resp)
			if scenario == "absent" {
				noErrors(t, resp.Diagnostics)
				require.True(t, resp.State.Raw.IsNull(), "missing actor remains in state")
			} else {
				require.True(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
				require.True(t, resp.State.Raw.Equal(state.Raw), "failed refresh must retain state")
				require.NotContains(t, fmt.Sprint(resp.Diagnostics), "test-secret-not-a-credential")
			}
		})
	}
}

func TestActorImportDoesNotInventSecret(t *testing.T) {
	r := &actorResource{client: testControl{
		actors: func(control.ListCTSActorsOptions) (control.CTSActorPage, error) {
			return control.CTSActorPage{Items: []control.CTSActor{{ID: "app-imported", Name: "imported", Kind: "app", CreatedAt: "today"}}}, nil
		},
		keys: func() ([]control.CTSAccessKeyMetadata, error) {
			return []control.CTSAccessKeyMetadata{{ID: "key-imported", Name: "imported", Role: "member"}}, nil
		},
	}}
	imported := resource.ImportStateResponse{State: resourceState(t, r, actorModel{})}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "app-imported"}, &imported)
	noErrors(t, imported.Diagnostics)
	refreshed := resource.ReadResponse{State: imported.State}
	r.Read(context.Background(), resource.ReadRequest{State: imported.State}, &refreshed)
	noErrors(t, refreshed.Diagnostics)
	var state actorModel
	noErrors(t, refreshed.State.Get(context.Background(), &state))
	require.True(t, state.AccessKey.IsNull())
	require.True(t, state.TokenExpiry.IsNull())
	require.Equal(t, "key-imported", state.KeyID.ValueString())
}

func TestClientRefreshPreservesSecretAndExternalGrants(t *testing.T) {
	for _, scenario := range []string{"external grants", "missing tracked grant", "absent", "failed list"} {
		t.Run(scenario, func(t *testing.T) {
			r := &clientResource{client: testControl{clients: func() ([]control.ZeroKMSClient, error) {
				switch scenario {
				case "absent":
					return nil, nil
				case "failed list":
					return nil, control.ErrAuthentication
				case "missing tracked grant":
					return []control.ZeroKMSClient{{ID: clientID, Name: "renamed", Description: "new description", KeysetIDs: []string{tenantKeysetID}}}, nil
				default:
					return []control.ZeroKMSClient{{ID: clientID, Name: "renamed", Description: "new description", KeysetIDs: []string{tenantKeysetID, keysetID}}}, nil
				}
			}}}
			before := savedClient()
			state := resourceState(t, r, before)
			resp := resource.ReadResponse{State: state}
			r.Read(context.Background(), resource.ReadRequest{State: state}, &resp)
			switch scenario {
			case "absent":
				noErrors(t, resp.Diagnostics)
				require.True(t, resp.State.Raw.IsNull(), "absent client remains in state")
			case "failed list":
				require.True(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
				require.True(t, resp.State.Raw.Equal(state.Raw), "failed refresh must retain state")
			default:
				noErrors(t, resp.Diagnostics)
				var after clientModel
				noErrors(t, resp.State.Get(context.Background(), &after))
				require.Equal(t, "renamed", after.Name.ValueString())
				require.Equal(t, "new description", after.Description.ValueString())
				require.True(t, after.ClientKey.Equal(before.ClientKey), "refresh lost secret")
				require.True(t, after.KeysetID.Equal(before.KeysetID), "refresh lost tracked grant")
			}
		})
	}
}

func TestClientImportPreservesHistoricalMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		grants   []string
		want     string
		fail     bool
	}{
		{"single", clientID, []string{keysetID}, "", false},
		{"multiple", clientID, []string{tenantKeysetID, keysetID}, "", false},
		{"explicit second", clientID + "/" + keysetID, []string{tenantKeysetID, keysetID}, keysetID, false},
		{"missing selected", clientID + "/" + keysetID, []string{tenantKeysetID}, keysetID, false},
		{"no grants", clientID, nil, "", false},
		{"invalid uuid", "not-a-uuid", nil, "", true},
		{"too many segments", clientID + "/" + keysetID + "/extra", nil, "", true},
		{"missing object", clientID, nil, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &clientResource{client: testControl{clients: func() ([]control.ZeroKMSClient, error) {
				if tc.name == "missing object" {
					return nil, nil
				}

				return []control.ZeroKMSClient{{ID: clientID, Name: "imported", Description: "imported description", KeysetIDs: tc.grants}}, nil
			}}}
			resp := resource.ImportStateResponse{State: resourceState(t, r, clientModel{})}
			r.ImportState(context.Background(), resource.ImportStateRequest{ID: tc.id}, &resp)
			require.Equal(t, tc.fail, resp.Diagnostics.HasError(), "unexpected import diagnostics: %v", resp.Diagnostics)
			if tc.fail {
				return
			}

			var state clientModel
			noErrors(t, resp.State.Get(context.Background(), &state))
			require.Equal(t, clientID, state.ID.ValueString())
			require.Equal(t, tc.want, state.KeysetID.ValueString())
			require.Equal(t, tc.want == "", state.KeysetID.IsNull())
			require.True(t, state.ClientKey.IsNull(), "import invented secret")
		})
	}
}

func TestDeleteAlreadyAbsentAndFailures(t *testing.T) {
	for _, err := range []error{nil, fmt.Errorf("wrapped: %w", control.ErrNotFound), control.ErrForbidden} {
		actor := &actorResource{client: testControl{deleteActor: func(id string) error {
			require.Equal(t, "app-actor", id, "wrong actor deleted")
			return err
		}}}
		client := &clientResource{client: testControl{deleteClient: func(id string) error {
			require.Equal(t, clientID, id, "wrong client deleted")
			return err
		}}}
		for _, tc := range []struct {
			r     resource.Resource
			model any
		}{{actor, savedActor()}, {client, savedClient()}} {
			state := resourceState(t, tc.r, tc.model)
			resp := resource.DeleteResponse{State: state}
			tc.r.Delete(context.Background(), resource.DeleteRequest{State: state}, &resp)
			require.Equal(t, errors.Is(err, control.ErrForbidden), resp.Diagnostics.HasError(), "wrong delete result: %v", resp.Diagnostics)
		}
	}
}

func TestClientDataSourceRead(t *testing.T) {
	for _, scenario := range []string{"multiple grants", "no grants", "missing", "failed list", "invalid id"} {
		t.Run(scenario, func(t *testing.T) {
			d := &clientDataSource{client: testControl{clients: func() ([]control.ZeroKMSClient, error) {
				if scenario == "failed list" {
					return nil, errors.New("upstream body test-secret-not-a-credential")
				}

				clients := []control.ZeroKMSClient{{ID: "44444444-4444-4444-8444-444444444444", Name: "unrelated", KeysetIDs: []string{tenantKeysetID}}}
				if scenario != "missing" {
					grants := []string{tenantKeysetID, keysetID}
					if scenario == "no grants" {
						grants = []string{}
					}

					clients = append(clients, control.ZeroKMSClient{ID: clientID, Name: "existing", Description: "current description", KeysetIDs: grants})
				}

				return clients, nil
			}}}
			var schema datasource.SchemaResponse
			d.Schema(context.Background(), datasource.SchemaRequest{}, &schema)
			config := tfsdk.State{Schema: schema.Schema}
			id := clientID
			if scenario == "invalid id" {
				id = "not-a-uuid"
			}

			noErrors(t, config.Set(context.Background(), clientDataModel{
				ID: types.StringValue(id), Name: types.StringUnknown(), Description: types.StringUnknown(), KeysetIDs: types.SetUnknown(types.StringType),
			}))
			resp := datasource.ReadResponse{State: tfsdk.State{Schema: schema.Schema}}
			d.Read(context.Background(), datasource.ReadRequest{Config: tfsdk.Config{Schema: schema.Schema, Raw: config.Raw}}, &resp)
			if scenario == "missing" || scenario == "failed list" || scenario == "invalid id" {
				require.True(t, resp.Diagnostics.HasError(), "invalid or failed lookup must report an error")
				require.NotContains(t, fmt.Sprint(resp.Diagnostics), "test-secret-not-a-credential")

				return
			}

			noErrors(t, resp.Diagnostics)
			var result clientDataModel
			noErrors(t, resp.State.Get(context.Background(), &result))
			require.Equal(t, clientID, result.ID.ValueString())
			require.Equal(t, "existing", result.Name.ValueString())
			require.Equal(t, "current description", result.Description.ValueString())
			var grants []string
			noErrors(t, result.KeysetIDs.ElementsAs(context.Background(), &grants, false))
			require.False(t, result.KeysetIDs.IsNull(), "grants must be a known set, including when empty")
			require.False(t, result.KeysetIDs.IsUnknown(), "grants must be a known set, including when empty")
			if scenario == "no grants" {
				require.Empty(t, grants, "lookup invented a grant")
			} else {
				require.ElementsMatch(t, []string{keysetID, tenantKeysetID}, grants, "lookup must return all grants without selecting one")
			}
		})
	}
}

func TestKeysetGrantCreateStateOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		alreadyPresent, preflightError bool
		writeError, readError, present bool
		wantError, wantState           bool
	}{
		{name: "created", present: true, wantState: true},
		{name: "existing grant requires import", alreadyPresent: true, wantError: true},
		{name: "failed preflight", preflightError: true, wantError: true},
		{name: "rejected write", writeError: true, wantError: true},
		{name: "write took effect despite error", writeError: true, present: true, wantError: true, wantState: true},
		{name: "write outcome unknown", writeError: true, readError: true, wantError: true, wantState: true},
		{name: "failed confirmation", readError: true, wantError: true, wantState: true},
		{name: "not visible after success", wantError: true, wantState: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempted := false
			r := &keysetGrantResource{client: testControl{
				clients: func() ([]control.ZeroKMSClient, error) {
					if (!attempted && tc.preflightError) || (attempted && tc.readError) {
						return nil, control.ErrForbidden
					}

					grants := []string{tenantKeysetID}
					if tc.alreadyPresent || (attempted && tc.present) {
						grants = append(grants, keysetID)
					}

					return []control.ZeroKMSClient{{ID: clientID, KeysetIDs: grants}}, nil
				},
				grant: func(keyset, client string) error {
					require.False(t, attempted || tc.alreadyPresent || tc.preflightError, "unexpected grant mutation")
					require.Equal(t, keysetID, keyset)
					require.Equal(t, clientID, client)
					attempted = true
					if tc.writeError {
						return errors.New("upstream body test-secret-not-a-credential")
					}

					return nil
				},
			}}
			plan := resourceState(t, r, keysetGrantModel{ID: types.StringUnknown(), ClientID: types.StringValue(clientID), KeysetID: types.StringValue(keysetID)})
			resp := resource.CreateResponse{State: tfsdk.State{Schema: plan.Schema}}
			r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan(plan)}, &resp)
			require.Equal(t, tc.wantError, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
			require.Equal(t, !tc.wantState, resp.State.Raw.IsNull())
			require.NotContains(t, fmt.Sprint(resp.Diagnostics), "test-secret-not-a-credential")
			if tc.wantState {
				var saved keysetGrantModel
				noErrors(t, resp.State.Get(context.Background(), &saved))
				require.Equal(t, clientID+"/"+keysetID, saved.ID.ValueString())
				require.Equal(t, clientID, saved.ClientID.ValueString())
				require.Equal(t, keysetID, saved.KeysetID.ValueString())
			}
		})
	}
}

func TestKeysetGrantRefreshAndImport(t *testing.T) {
	for _, scenario := range []string{"present", "missing grant", "missing client", "failed list"} {
		t.Run(scenario, func(t *testing.T) {
			r := &keysetGrantResource{client: testControl{clients: func() ([]control.ZeroKMSClient, error) {
				if scenario == "failed list" {
					return nil, control.ErrAuthentication
				}

				// A grant to a different client must never satisfy this pair.
				clients := []control.ZeroKMSClient{{ID: "44444444-4444-4444-8444-444444444444", KeysetIDs: []string{keysetID}}}
				if scenario != "missing client" {
					grants := []string{tenantKeysetID}
					if scenario == "present" {
						grants = append(grants, keysetID)
					}

					clients = append(clients, control.ZeroKMSClient{ID: clientID, KeysetIDs: grants})
				}

				return clients, nil
			}}}
			before := resourceState(t, r, keysetGrantModel{ID: types.StringValue(clientID + "/" + keysetID), ClientID: types.StringValue(clientID), KeysetID: types.StringValue(keysetID)})
			read := resource.ReadResponse{State: before}
			r.Read(context.Background(), resource.ReadRequest{State: before}, &read)
			require.Equal(t, scenario == "failed list", read.Diagnostics.HasError(), "%v", read.Diagnostics)
			if scenario == "present" || scenario == "failed list" {
				require.True(t, read.State.Raw.Equal(before.Raw), "refresh lost the grant identity")
			} else {
				require.True(t, read.State.Raw.IsNull(), "absent pair remains in state")
			}

			for _, id := range []string{clientID + "/" + keysetID, clientID, clientID + "/not-a-uuid", clientID + "/" + keysetID + "/extra"} {
				imported := resource.ImportStateResponse{State: tfsdk.State{Schema: before.Schema}}
				r.ImportState(context.Background(), resource.ImportStateRequest{ID: id}, &imported)
				valid := scenario == "present" && id == clientID+"/"+keysetID
				require.Equal(t, !valid, imported.Diagnostics.HasError(), "import %s: %v", id, imported.Diagnostics)
				if valid {
					require.True(t, imported.State.Raw.Equal(before.Raw), "import chose a different grant")
				}
			}
		})
	}
}

func TestKeysetGrantDeleteRequiresConfirmedAbsence(t *testing.T) {
	for _, tc := range []struct {
		name                                       string
		absent, preflightError, writeError         bool
		readError, stillPresent, wantError, warned bool
	}{
		{name: "already absent", absent: true},
		{name: "revoked"},
		{name: "preflight failed", preflightError: true, wantError: true},
		{name: "revoked despite error", writeError: true, warned: true},
		{name: "revoke failed", writeError: true, stillPresent: true, wantError: true},
		{name: "confirmation failed", readError: true, wantError: true},
		{name: "still present after success", stillPresent: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempted := false
			r := &keysetGrantResource{client: testControl{
				clients: func() ([]control.ZeroKMSClient, error) {
					if (!attempted && tc.preflightError) || (attempted && tc.readError) {
						return nil, control.ErrForbidden
					}

					grants := []string{tenantKeysetID}
					if !tc.absent && (!attempted || tc.stillPresent) {
						grants = append(grants, keysetID)
					}

					return []control.ZeroKMSClient{{ID: clientID, KeysetIDs: grants}}, nil
				},
				revoke: func(keyset, client string) error {
					require.False(t, attempted || tc.absent || tc.preflightError, "unexpected revoke mutation")
					require.Equal(t, keysetID, keyset)
					require.Equal(t, clientID, client)
					attempted = true
					if tc.writeError {
						return errors.New("service failed")
					}

					return nil
				},
			}}
			before := resourceState(t, r, keysetGrantModel{ID: types.StringValue(clientID + "/" + keysetID), ClientID: types.StringValue(clientID), KeysetID: types.StringValue(keysetID)})
			resp := resource.DeleteResponse{State: before}
			r.Delete(context.Background(), resource.DeleteRequest{State: before}, &resp)
			require.Equal(t, tc.wantError, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
			require.Equal(t, tc.warned, resp.Diagnostics.WarningsCount() > 0)
			if tc.wantError {
				require.True(t, resp.State.Raw.Equal(before.Raw), "failed delete discarded the grant identity")
			}
		})
	}
}

func TestKeysetCreateRetainsIdentityOnSupplementalFailure(t *testing.T) {
	for _, scenario := range []string{"enabled", "disabled", "create failed", "disable failed", "read failed", "not visible"} {
		t.Run(scenario, func(t *testing.T) {
			var result resource.CreateResponse
			remote := control.ZeroKMSKeyset{ID: keysetID, Name: "created", Description: "creation description"}
			r := &keysetResource{client: testControl{
				createKeyset: func(opts control.CreateZeroKMSKeysetOptions) (*control.CreatedZeroKMSKeyset, error) {
					require.Equal(t, "created", opts.Name)
					require.Equal(t, "creation description", opts.Description)
					require.Nil(t, opts.Client, "keyset creation must not create a client")
					if scenario == "create failed" {
						return nil, control.ErrConflict
					}

					return &control.CreatedZeroKMSKeyset{ZeroKMSKeyset: remote}, nil
				},
				disableKeyset: func(id string) error {
					var saved keysetModel
					noErrors(t, result.State.Get(context.Background(), &saved))
					require.Equal(t, keysetID, saved.ID.ValueString(), "disable began before the created identity was saved")
					require.Equal(t, keysetID, id)
					if scenario == "disable failed" {
						return control.ErrForbidden
					}

					remote.IsDisabled = true

					return nil
				},
				keysets: func(opts control.ListZeroKMSKeysetsOptions) ([]control.ZeroKMSKeyset, error) {
					require.True(t, opts.ShowDisabled, "disabled keysets must remain visible during reconciliation")
					if scenario == "read failed" {
						return nil, control.ErrAuthentication
					}

					if scenario == "not visible" {
						return nil, nil
					}

					return []control.ZeroKMSKeyset{remote}, nil
				},
			}}
			plan := resourceState(t, r, keysetModel{ID: types.StringUnknown(), Name: types.StringValue("created"), Description: types.StringValue("creation description"), Enabled: types.BoolValue(scenario == "enabled"), IsDefault: types.BoolUnknown()})
			result = resource.CreateResponse{State: tfsdk.State{Schema: plan.Schema}}
			r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan(plan)}, &result)
			require.Equal(t, scenario != "enabled" && scenario != "disabled", result.Diagnostics.HasError(), "%v", result.Diagnostics)
			if scenario == "create failed" {
				require.True(t, result.State.Raw.IsNull(), "failed creation invented an identity")
				return
			}

			var saved keysetModel
			noErrors(t, result.State.Get(context.Background(), &saved))
			require.Equal(t, keysetID, saved.ID.ValueString())
			require.Equal(t, "created", saved.Name.ValueString())
			require.Equal(t, scenario == "enabled" || scenario == "disable failed", saved.Enabled.ValueBool())
			require.False(t, saved.IsDefault.ValueBool())
		})
	}
}

func TestKeysetReadAndImportIncludeDisabled(t *testing.T) {
	for _, scenario := range []string{"disabled", "missing", "failed list"} {
		t.Run(scenario, func(t *testing.T) {
			r := &keysetResource{client: testControl{keysets: func(opts control.ListZeroKMSKeysetsOptions) ([]control.ZeroKMSKeyset, error) {
				if scenario == "failed list" {
					return nil, control.ErrForbidden
				}

				keysets := []control.ZeroKMSKeyset{{ID: tenantKeysetID, Name: "unrelated", Description: "unrelated"}}
				if opts.ShowDisabled && scenario != "missing" {
					keysets = append(keysets, control.ZeroKMSKeyset{ID: keysetID, Name: "renamed", Description: "new description", IsDisabled: true, IsDefault: true})
				}

				return keysets, nil
			}}}
			before := resourceState(t, r, keysetModel{ID: types.StringValue(keysetID), Name: types.StringValue("before"), Description: types.StringValue("before"), Enabled: types.BoolValue(true), IsDefault: types.BoolValue(false)})
			read := resource.ReadResponse{State: before}
			r.Read(context.Background(), resource.ReadRequest{State: before}, &read)
			require.Equal(t, scenario == "failed list", read.Diagnostics.HasError(), "%v", read.Diagnostics)
			if scenario == "failed list" {
				require.True(t, read.State.Raw.Equal(before.Raw), "failed read discarded state")
			}

			if scenario == "missing" {
				require.True(t, read.State.Raw.IsNull(), "missing keyset remains in state")
			}

			for _, id := range []string{keysetID, "not-a-uuid"} {
				imported := resource.ImportStateResponse{State: tfsdk.State{Schema: before.Schema}}
				r.ImportState(context.Background(), resource.ImportStateRequest{ID: id}, &imported)
				valid := id == keysetID && scenario == "disabled"
				require.Equal(t, !valid, imported.Diagnostics.HasError(), "%v", imported.Diagnostics)
				if valid {
					var saved keysetModel
					noErrors(t, imported.State.Get(context.Background(), &saved))
					require.Equal(t, keysetID, saved.ID.ValueString())
					require.Equal(t, "renamed", saved.Name.ValueString())
					require.Equal(t, "new description", saved.Description.ValueString())
					require.False(t, saved.Enabled.ValueBool())
					require.True(t, saved.IsDefault.ValueBool())
					require.True(t, read.State.Raw.Equal(imported.State.Raw), "refresh/import disagree")
				}
			}
		})
	}
}

func TestKeysetUpdatePreservesPartialSuccess(t *testing.T) {
	for _, scenario := range []string{"success", "modify failed", "disable failed", "read failed", "write not visible"} {
		t.Run(scenario, func(t *testing.T) {
			remote := control.ZeroKMSKeyset{ID: keysetID, Name: "unchanged", Description: "old description"}
			r := &keysetResource{client: testControl{
				modifyKeyset: func(id string, opts control.ModifyZeroKMSKeysetOptions) error {
					require.Equal(t, keysetID, id)
					require.Nil(t, opts.Name, "metadata update must only send the changed description")
					require.NotNil(t, opts.Description)
					require.Equal(t, "new description", *opts.Description)
					if scenario == "modify failed" {
						return control.ErrForbidden
					}

					remote.Description = *opts.Description

					return nil
				},
				disableKeyset: func(id string) error {
					require.NotEqual(t, "modify failed", scenario, "unexpected enablement mutation")
					require.Equal(t, keysetID, id)
					if scenario == "disable failed" {
						return errors.New("uncertain write: test-secret-not-a-credential")
					}

					if scenario != "write not visible" {
						remote.IsDisabled = true
					}

					return nil
				},
				keysets: func(control.ListZeroKMSKeysetsOptions) ([]control.ZeroKMSKeyset, error) {
					if scenario == "read failed" {
						return nil, control.ErrAuthentication
					}

					return []control.ZeroKMSKeyset{remote}, nil
				},
			}}
			before := resourceState(t, r, keysetModel{ID: types.StringValue(keysetID), Name: types.StringValue("unchanged"), Description: types.StringValue("old description"), Enabled: types.BoolValue(true), IsDefault: types.BoolValue(false)})
			plan := resourceState(t, r, keysetModel{ID: types.StringValue(keysetID), Name: types.StringValue("unchanged"), Description: types.StringValue("new description"), Enabled: types.BoolValue(false), IsDefault: types.BoolUnknown()})
			updated := resource.UpdateResponse{State: before}
			r.Update(context.Background(), resource.UpdateRequest{State: before, Plan: tfsdk.Plan(plan)}, &updated)
			require.Equal(t, scenario != "success", updated.Diagnostics.HasError(), "%v", updated.Diagnostics)
			require.NotContains(t, fmt.Sprint(updated.Diagnostics), "test-secret-not-a-credential")
			var saved keysetModel
			noErrors(t, updated.State.Get(context.Background(), &saved))
			wantDescription := "new description"
			if scenario == "modify failed" {
				wantDescription = "old description"
			}

			require.Equal(t, keysetID, saved.ID.ValueString())
			require.Equal(t, wantDescription, saved.Description.ValueString())
			require.Equal(t, scenario == "modify failed" || scenario == "disable failed" || scenario == "write not visible", saved.Enabled.ValueBool())
		})
	}
}

func TestKeysetDestroyRequiresConfirmedDisablement(t *testing.T) {
	for _, scenario := range []string{"enabled", "disabled", "missing", "preflight failed", "disable failed", "read failed", "still enabled"} {
		t.Run(scenario, func(t *testing.T) {
			attempted := false
			r := &keysetResource{client: testControl{
				keysets: func(opts control.ListZeroKMSKeysetsOptions) ([]control.ZeroKMSKeyset, error) {
					require.True(t, opts.ShowDisabled, "destroy must include disabled keysets")
					if scenario == "preflight failed" || (attempted && scenario == "read failed") {
						return nil, control.ErrForbidden
					}

					if scenario == "missing" {
						return nil, nil
					}

					return []control.ZeroKMSKeyset{{ID: keysetID, Name: "retained", Description: "retained description", IsDisabled: scenario == "disabled" || (attempted && scenario != "still enabled")}}, nil
				},
				disableKeyset: func(id string) error {
					require.False(t, attempted, "unexpected disable mutation")
					require.NotEqual(t, "disabled", scenario)
					require.Equal(t, keysetID, id)
					attempted = true
					if scenario == "disable failed" {
						return control.ErrNotFound
					}

					return nil
				},
			}}
			// Prior state says disabled; live inventory, not this stale value,
			// must decide whether destroy needs to disable the keyset.
			before := resourceState(t, r, keysetModel{ID: types.StringValue(keysetID), Name: types.StringValue("retained"), Description: types.StringValue("retained description"), Enabled: types.BoolValue(false), IsDefault: types.BoolValue(false)})
			deleted := resource.DeleteResponse{State: before}
			r.Delete(context.Background(), resource.DeleteRequest{State: before}, &deleted)
			wantError := scenario != "enabled" && scenario != "disabled" && scenario != "missing"
			require.Equal(t, wantError, deleted.Diagnostics.HasError(), "%v", deleted.Diagnostics)
			require.Equal(t, scenario == "enabled" || scenario == "disabled", deleted.Diagnostics.WarningsCount() > 0)
			if wantError {
				require.True(t, deleted.State.Raw.Equal(before.Raw), "failed destroy discarded keyset identity")
			}
		})
	}
}
