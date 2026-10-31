package provider

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	control "github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/manage"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSDKReadFailureIsNotAbsence(t *testing.T) {
	for _, kind := range []string{"actor", "client", "keyset", "grant"} {
		for _, status := range []int{0, 401, 403, 404, 500} {
			t.Run(fmt.Sprintf("%s/%d", kind, status), func(t *testing.T) {
				f := newServiceFixture(t)
				f.keysets = nil
				client := fixtureClient(t, fixtureTransport(t, "admin", f.ServeHTTP))
				var r resource.Resource
				var model any
				var endpoint string
				switch kind {
				case "actor":
					r, model, endpoint = &actorResource{client: client}, savedActor(), "/api/actors"
				case "client":
					r, model, endpoint = &clientResource{client: client}, savedClient(), "/list-clients"
				case "keyset":
					r, model, endpoint = &keysetResource{client: client}, keysetModel{ID: types.StringValue(keysetID), Name: types.StringValue("application"), Description: types.StringValue("owned"), Enabled: types.BoolValue(true), IsDefault: types.BoolValue(false)}, "/list-keysets"
				case "grant":
					r, model, endpoint = &keysetGrantResource{client: client}, keysetGrantModel{ID: types.StringValue(clientID + "/" + keysetID), ClientID: types.StringValue(clientID), KeysetID: types.StringValue(keysetID)}, "/list-clients"
				}

				if status != 0 {
					f.faults = []serviceFault{{path: endpoint, status: status}}
				}

				before := resourceState(t, r, model)
				resp := resource.ReadResponse{State: before}
				r.Read(context.Background(), resource.ReadRequest{State: before}, &resp)
				if status == 0 {
					noErrors(t, resp.Diagnostics)
					require.True(t, resp.State.Raw.IsNull(), "confirmed absence retained state")
				} else {
					require.True(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
					require.True(t, resp.State.Raw.Equal(before.Raw), "failed inventory read lost state")
					require.NotContains(t, fmt.Sprint(resp.Diagnostics), "fixture-upstream-secret")
				}

				f.edit(func() {
					require.Empty(t, f.mutations, "refresh mutated inventory")
				})
			})
		}
	}
}

func TestMalformedInventoryPreservesState(t *testing.T) {
	for _, kind := range []string{"client", "keyset", "grant"} {
		for _, malformed := range []string{"invalid UUID", "duplicate ID", "escaped duplicate ID", "case duplicate ID", "missing description", "null description", "invalid grant UUID", "duplicate grants"} {
			if kind == "keyset" && (malformed == "invalid grant UUID" || malformed == "duplicate grants") {
				continue
			}

			t.Run(kind+"/"+malformed, func(t *testing.T) {
				id := clientID
				endpoint := "/list-clients"
				if kind == "keyset" {
					id, endpoint = keysetID, "/list-keysets"
				}

				body := fmt.Sprintf(`[{"id":%q,"name":"application","description":"owned","keyset_id":[%q],"is_disabled":false}]`, id, keysetID)
				switch malformed {
				case "invalid UUID":
					body = strings.Replace(body, id, "fixture-upstream-secret", 1)
				case "duplicate ID", "escaped duplicate ID", "case duplicate ID":
					field := "id"
					switch malformed {
					case "escaped duplicate ID":
						field = `\u0069d`
					case "case duplicate ID":
						field = "ID"
					}

					body = strings.Replace(body, `"id":`, fmt.Sprintf(`"%s":%q,"id":`, field, tenantKeysetID), 1)
				case "missing description":
					body = strings.Replace(body, `,"description":"owned"`, "", 1)
				case "null description":
					body = strings.Replace(body, `"description":"owned"`, `"description":null`, 1)
				case "invalid grant UUID":
					body = strings.Replace(body, keysetID, "fixture-upstream-secret", 1)
				case "duplicate grants":
					body = strings.Replace(body, `"keyset_id":`, `"keyset_id":[],"keyset_id":`, 1)
				}

				client := fixtureClient(t, fixtureTransport(t, "admin", func(w http.ResponseWriter, req *http.Request) {
					assert.Equal(t, endpoint, req.URL.Path, "refresh must only read inventory")
					_, _ = fmt.Fprint(w, body)
				}))
				var r resource.Resource
				var model any
				switch kind {
				case "client":
					r, model = &clientResource{client: client}, savedClient()
				case "keyset":
					r, model = &keysetResource{client: client}, keysetModel{ID: types.StringValue(keysetID), Name: types.StringValue("application"), Description: types.StringValue("owned"), Enabled: types.BoolValue(true), IsDefault: types.BoolValue(false)}
				case "grant":
					r, model = &keysetGrantResource{client: client}, keysetGrantModel{ID: types.StringValue(clientID + "/" + keysetID), ClientID: types.StringValue(clientID), KeysetID: types.StringValue(keysetID)}
				}

				before := resourceState(t, r, model)
				resp := resource.ReadResponse{State: before}
				r.Read(t.Context(), resource.ReadRequest{State: before}, &resp)
				require.True(t, resp.Diagnostics.HasError(), "malformed inventory must fail refresh")
				require.True(t, resp.State.Raw.Equal(before.Raw), "malformed inventory changed persisted identity, metadata or secret")
				require.NotContains(t, fmt.Sprint(resp.Diagnostics), "fixture-upstream-secret")
			})
		}
	}
}

func TestSDKActorPaginationAndMetadata(t *testing.T) {
	for _, scenario := range []string{"later page", "repeated cursor", "missing metadata", "ambiguous metadata"} {
		t.Run(scenario, func(t *testing.T) {
			f := newServiceFixture(t)
			f.actors = []control.CTSActor{{ID: "app-other", Name: "other", Kind: "app"}, {ID: "app-actor", Name: "renamed", Kind: "app", CreatedAt: fixtureTimestamp}}
			f.keys = []control.CTSAccessKeyMetadata{{ID: "key-1", Name: "renamed", Role: "control", CreatedAt: fixtureTimestamp}}
			model := savedActor()
			switch scenario {
			case "repeated cursor":
				f.repeatCursor = true
			case "missing metadata":
				f.keys = nil
			case "ambiguous metadata":
				model.KeyID = types.StringNull()
				f.keys = append(f.keys, control.CTSAccessKeyMetadata{ID: "another-key", Name: "renamed", Role: "member"})
			}

			r := &actorResource{client: fixtureClient(t, fixtureTransport(t, "admin", f.ServeHTTP))}
			before := resourceState(t, r, model)
			resp := resource.ReadResponse{State: before}
			r.Read(context.Background(), resource.ReadRequest{State: before}, &resp)
			if scenario != "later page" {
				require.True(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
				require.True(t, resp.State.Raw.Equal(before.Raw), "incomplete inventory forgot or altered the actor")

				return
			}

			noErrors(t, resp.Diagnostics)
			var got actorModel
			noErrors(t, resp.State.Get(context.Background(), &got))
			require.Equal(t, model.ID, got.ID)
			require.Equal(t, model.AccessKey, got.AccessKey)
			require.Equal(t, model.TokenExpiry, got.TokenExpiry)
			require.Equal(t, "renamed", got.Name.ValueString())
			require.Equal(t, "control", got.Role.ValueString())
		})
	}
}

func TestSDKKeysetPartialWrites(t *testing.T) {
	for _, test := range []struct {
		name, endpoint, description           string
		afterWrite, enabled, initiallyEnabled bool
	}{
		{"metadata rejected", "/modify-keyset", "Worker owned", false, true, true},
		{"metadata applied then error", "/modify-keyset", "updated", true, true, true},
		{"disable rejected", "/disable-keyset", "updated", false, true, true},
		{"disable applied then error", "/disable-keyset", "updated", true, false, true},
		{"confirmation failed", "/list-keysets", "updated", false, false, true},
		{"enable rejected", "/enable-keyset", "Worker owned", false, false, false},
		{"enable applied then error", "/enable-keyset", "Worker owned", true, true, false},
		{"metadata and confirmation rejected after enable", "/modify-keyset", "Worker owned", false, true, false},
		{"metadata applied then error after enable", "/modify-keyset", "updated", true, true, false},
		{"confirmation failed after enable", "/list-keysets", "updated", false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newServiceFixture(t)
			f.keysets[1].IsDisabled = !test.initiallyEnabled
			f.faults = []serviceFault{{path: test.endpoint, afterWrite: test.afterWrite, status: 500}}
			if test.name == "metadata and confirmation rejected after enable" {
				f.faults = append(f.faults, serviceFault{path: "/list-keysets", status: 500})
			}
			r := &keysetResource{client: fixtureClient(t, fixtureTransport(t, "admin", f.ServeHTTP))}
			model := keysetModel{ID: types.StringValue(tenantKeysetID), Name: types.StringValue("external"), Description: types.StringValue("Worker owned"), Enabled: types.BoolValue(test.initiallyEnabled), IsDefault: types.BoolValue(false)}
			before := resourceState(t, r, model)
			model.Description, model.Enabled = types.StringValue("updated"), types.BoolValue(!test.initiallyEnabled)
			plan := resourceState(t, r, model)
			resp := resource.UpdateResponse{State: before}
			r.Update(context.Background(), resource.UpdateRequest{State: before, Plan: tfsdk.Plan(plan)}, &resp)
			require.True(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
			require.NotContains(t, fmt.Sprint(resp.Diagnostics), "fixture-upstream-secret")
			var got keysetModel
			noErrors(t, resp.State.Get(context.Background(), &got))
			require.Equal(t, tenantKeysetID, got.ID.ValueString())
			require.Equal(t, test.description, got.Description.ValueString())
			require.Equal(t, test.enabled, got.Enabled.ValueBool())
			f.edit(func() {
				assert.Equal(t, test.description, f.keysets[1].Description)
				assert.Equal(t, !test.enabled, f.keysets[1].IsDisabled)
				attempts := 0
				for _, path := range f.requests {
					if path == test.endpoint {
						attempts++
					}
				}

				assert.Equal(t, 1, attempts, "failed operation was retried")
			})
		})
	}
}

func TestSDKGrantUncertainWrites(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		for _, applied := range []bool{false, true} {
			for _, readFailed := range []bool{false, true} {
				t.Run(fmt.Sprintf("revoke=%t/applied=%t/readFailed=%t", revoke, applied, readFailed), func(t *testing.T) {
					f := newServiceFixture(t)
					f.clients = []control.ZeroKMSClient{{ID: clientID, Name: "existing", KeysetIDs: []string{keysetID}}}
					endpoint := "/grant-keyset"
					if revoke {
						endpoint = "/revoke-keyset"
						f.clients[0].KeysetIDs = append(f.clients[0].KeysetIDs, tenantKeysetID)
					}

					f.faults = []serviceFault{{path: endpoint, afterWrite: applied, status: 500}}
					if readFailed {
						f.faults = append(f.faults, serviceFault{path: "/list-clients", skip: 1, status: 500})
					}

					r := &keysetGrantResource{client: fixtureClient(t, fixtureTransport(t, "admin", f.ServeHTTP))}
					model := keysetGrantModel{ID: types.StringValue(clientID + "/" + tenantKeysetID), ClientID: types.StringValue(clientID), KeysetID: types.StringValue(tenantKeysetID)}
					before := resourceState(t, r, model)
					if revoke {
						resp := resource.DeleteResponse{State: before}
						r.Delete(context.Background(), resource.DeleteRequest{State: before}, &resp)
						confirmed := applied && !readFailed
						require.Equal(t, !confirmed, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
						require.Equal(t, confirmed, resp.Diagnostics.WarningsCount() == 1)
						require.True(t, resp.State.Raw.Equal(before.Raw), "revocation changed state")
						require.NotContains(t, fmt.Sprint(resp.Diagnostics), "fixture-upstream-secret")
					} else {
						resp := resource.CreateResponse{State: tfsdk.State{Schema: before.Schema}}
						r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan(before)}, &resp)
						require.True(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
						require.Equal(t, !applied && !readFailed, resp.State.Raw.IsNull())
						require.NotContains(t, fmt.Sprint(resp.Diagnostics), "fixture-upstream-secret")
						if !resp.State.Raw.IsNull() {
							require.True(t, resp.State.Raw.Equal(before.Raw), "uncertain grant retained the wrong pair")
						}
					}

					f.edit(func() {
						assert.Contains(t, f.clients[0].KeysetIDs, keysetID)
						assert.Equal(t, applied != revoke, slices.Contains(f.clients[0].KeysetIDs, tenantKeysetID))
						attempts := 0
						for _, path := range f.requests {
							if path == endpoint {
								attempts++
							}
						}

						assert.Equal(t, 1, attempts, "uncertain write must not retry")
					})
				})
			}
		}
	}
}

func TestSDKKeysetDestroyConfirmation(t *testing.T) {
	f := newServiceFixture(t)
	f.faults = []serviceFault{{path: "/list-keysets", skip: 1, status: 500}}
	r := &keysetResource{client: fixtureClient(t, fixtureTransport(t, "admin", f.ServeHTTP))}
	before := resourceState(t, r, keysetModel{ID: types.StringValue(tenantKeysetID), Name: types.StringValue("external"), Description: types.StringValue("Worker owned"), Enabled: types.BoolValue(true), IsDefault: types.BoolValue(false)})
	resp := resource.DeleteResponse{State: before}
	r.Delete(context.Background(), resource.DeleteRequest{State: before}, &resp)
	require.True(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.True(t, resp.State.Raw.Equal(before.Raw), "unconfirmed destroy forgot the keyset")
	// A second destroy can confirm the already-disabled keyset without issuing
	// another write. The key material remains remotely after Terraform forgets it.
	resp = resource.DeleteResponse{State: before}
	r.Delete(context.Background(), resource.DeleteRequest{State: before}, &resp)
	noErrors(t, resp.Diagnostics)
	f.edit(func() {
		require.Len(t, f.keysets, 2)
		require.True(t, f.keysets[1].IsDisabled)
		require.Equal(t, []string{"/disable-keyset"}, f.mutations)
		require.Equal(t, 1, resp.Diagnostics.WarningsCount())
	})
}
