package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/control"
	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testCRN    = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"
	testIssuer = "https://ap-southeast-2.aws.cts.cipherstashmanaged.net/"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Exercise the real auth guest and SDK against fixture tokens and an
// httptest service. Requests cannot escape to a real CipherStash endpoint.
func fixtureTransport(t *testing.T, role string, handler http.HandlerFunc) http.RoundTripper {
	t.Helper()
	claims, err := json.Marshal(map[string]any{
		"iss": testIssuer, "sub": "provider-test", "workspace": "ZVATKW3VHMFG27DY",
		"iat": 1704067200, "exp": 4102444800, // Fixed 2024–2100 validity keeps seeded fixtures deterministic.
		"aud": "ap-southeast-2.aws.viturhosted.net", "role_set": role, "scope": []string{"read"},
		"services": map[string]string{"zerokms": "https://ap-southeast-2.aws.viturhosted.net/"},
	})
	require.NoError(t, err)
	// stack-auth reads the exchanged token; signatures and permission checks
	// belong to the services, so this fixture deliberately has no valid signature.
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("fixture-signature"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// net/http otherwise recovers a fixture panic as an ordinary connection
		// failure, which could accidentally satisfy an expected-error assertion.
		defer func() {
			if failure := recover(); failure != nil {
				assert.Failf(t, "fixture handler panicked", "%v", failure)
				http.Error(w, "fixture handler failed", http.StatusInternalServerError)
			}
		}()

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/authorise":
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"accessToken": token, "expiry": 4102444800}))
		default:
			assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"), "service did not receive the exchanged bearer")
			handler(w, r)
		}
	}))
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	require.NoError(t, err)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)

	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "ap-southeast-2.aws.cts.cipherstashmanaged.net" && req.URL.Host != "ap-southeast-2.aws.viturhosted.net" {
			assert.Failf(t, "unexpected fixture destination", "%s", req.URL.Host)
			return nil, fmt.Errorf("unexpected fixture destination")
		}

		local := req.Clone(req.Context())
		local.URL.Scheme, local.URL.Host = target.Scheme, target.Host

		return transport.RoundTrip(local)
	})
}

func configureFixture(t *testing.T, p *Provider, rt http.RoundTripper, cfg providerModel) frameworkprovider.ConfigureResponse {
	t.Helper()
	// Production Configure uses the SDK's default transport. Override only the
	// test process transport, not the provider's public configuration surface.
	previous := http.DefaultTransport
	http.DefaultTransport = rt
	t.Cleanup(func() { http.DefaultTransport = previous })
	var schema frameworkprovider.SchemaResponse
	p.Schema(context.Background(), frameworkprovider.SchemaRequest{}, &schema)
	state := tfsdk.State{Schema: schema.Schema}
	noErrors(t, state.Set(context.Background(), cfg))
	var resp frameworkprovider.ConfigureResponse
	p.Configure(context.Background(), frameworkprovider.ConfigureRequest{Config: tfsdk.Config{Schema: schema.Schema, Raw: state.Raw}}, &resp)

	return resp
}

func fixtureClient(t *testing.T, rt http.RoundTripper) *control.Client {
	t.Helper()
	store, err := auth.OpenWithoutProfile(context.Background(), auth.WithRoundTripper(rt))
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, store.Close(), "could not close SDK authentication store")
	})
	strategy, err := store.AccessKey(context.Background(), testCRN, auth.NewAccessKey([]byte("CSAKtestKeyId.testKeySecret")), auth.WithAcceptedRoles("Admin"))
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, strategy.Close(), "could not close SDK authentication strategy")
	})
	client, err := control.NewClient(context.Background(), testCRN, control.WithCTSAuth(strategy), control.WithZeroKMSAuth(strategy), control.WithTransport(rt))
	require.NoError(t, err)

	return client
}

func TestActorCreateSavesSecretBeforeMetadataRead(t *testing.T) {
	for _, metadataFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(metadataFailure), func(t *testing.T) {
			var result resource.CreateResponse
			rt := fixtureTransport(t, "admin", func(w http.ResponseWriter, req *http.Request) {
				switch req.URL.Path {
				case "/api/actors":
					var input control.CreateActorOptions
					assert.NoError(t, json.NewDecoder(req.Body).Decode(&input))
					assert.Equal(t, "test-create", input.Name)
					assert.Equal(t, "agent", input.Kind)
					assert.Equal(t, "control", input.Role)
					if assert.NotNil(t, input.TokenExpiry) {
						assert.Equal(t, int64(1234), *input.TokenExpiry)
					}

					_, err := fmt.Fprint(w, `{"actorId":"agent-created","name":"test-create","kind":"agent","role":"control","accessKey":"CSAKcreated.secret"}`)
					assert.NoError(t, err)
				case "/api/access-keys":
					// Assert state already contains the one-time material while the
					// supplemental request is in flight, not just after it returns.
					var saved actorModel
					d := result.State.Get(context.Background(), &saved)
					assert.False(t, d.HasError(), "%v", d)
					assert.Equal(t, "agent-created", saved.ID.ValueString())
					assert.Equal(t, "CSAKcreated.secret", saved.AccessKey.ValueString())
					if metadataFailure {
						http.Error(w, "body must not leak CSAKcreated.secret", 500)
						return
					}

					_, err := fmt.Fprint(w, `[{"keyId":"key-created","keyName":"test-create","role":"control","createdAt":"2026-10-26T00:00:00Z"}]`)
					assert.NoError(t, err)
				default:
					assert.Failf(t, "unexpected request", "%s", req.URL.Path)
					http.NotFound(w, req)
				}
			})
			r := &actorResource{client: fixtureClient(t, rt)}
			model := actorModel{Name: types.StringValue("test-create"), Kind: types.StringValue("agent"), Role: types.StringValue("control"), TokenExpiry: types.Int64Value(1234), ID: types.StringUnknown(), KeyID: types.StringUnknown(), AccessKey: types.StringUnknown(), CreatedAt: types.StringUnknown()}
			plan := resourceState(t, r, model)
			result = resource.CreateResponse{State: resourceState(t, r, actorModel{})}
			r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan(plan)}, &result)
			require.Equal(t, metadataFailure, result.Diagnostics.HasError(), "%v", result.Diagnostics)
			var saved actorModel
			noErrors(t, result.State.Get(context.Background(), &saved))
			require.Equal(t, "agent-created", saved.ID.ValueString())
			require.Equal(t, "CSAKcreated.secret", saved.AccessKey.ValueString())
			if !metadataFailure {
				require.Equal(t, "key-created", saved.KeyID.ValueString())
				require.Equal(t, "2026-10-26T00:00:00Z", saved.CreatedAt.ValueString())
			}
		})
	}
}

func TestClientCreatePreservesEncodedSecret(t *testing.T) {
	rt := fixtureTransport(t, "admin", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/create-client" {
			assert.Failf(t, "unexpected request", "%s", req.URL.Path)
			http.NotFound(w, req)

			return
		}

		var input map[string]any
		assert.NoError(t, json.NewDecoder(req.Body).Decode(&input))
		assert.Equal(t, "test-client", input["name"])
		assert.Equal(t, "create test", input["description"])
		assert.Nil(t, input["keyset_id"], "default keyset must be omitted")
		_, err := fmt.Fprintf(w, `{"id":%q,"name":"test-client","description":"create test","dataset_id":%q,"client_key":"AQIDBA=="}`, clientID, keysetID)
		assert.NoError(t, err)
	})
	r := &clientResource{client: fixtureClient(t, rt)}
	plan := resourceState(t, r, clientModel{Name: types.StringValue("test-client"), Description: types.StringValue("create test"), ID: types.StringUnknown(), KeysetID: types.StringUnknown(), ClientKey: types.StringUnknown()})
	resp := resource.CreateResponse{State: resourceState(t, r, clientModel{})}
	r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan(plan)}, &resp)
	noErrors(t, resp.Diagnostics)
	var state clientModel
	noErrors(t, resp.State.Get(context.Background(), &state))
	require.Equal(t, clientID, state.ID.ValueString())
	require.Equal(t, keysetID, state.KeysetID.ValueString())
	require.Equal(t, "AQIDBA==", state.ClientKey.ValueString())
}

func TestProviderOwnsSessionAcrossCallsAndClosesOnReconfigureAndStop(t *testing.T) {
	rt := fixtureTransport(t, "admin", func(w http.ResponseWriter, req *http.Request) {
		_, err := fmt.Fprint(w, `[]`)
		assert.NoError(t, err)
	})
	t.Setenv("CIPHERSTASH_ACCESS_KEY", "CSAKtestKeyId.testKeySecret")
	p := New()
	t.Cleanup(func() {
		assert.NoError(t, p.Close(), "could not close SDK authentication")
	})
	cfg := providerModel{CRN: types.StringValue(testCRN), AccessKey: types.StringNull()}
	configured := configureFixture(t, p, rt, cfg)
	noErrors(t, configured.Diagnostics)
	oldStrategy, oldStore := p.strategy, p.store
	_, err := oldStrategy.Token(context.Background())
	require.NoError(t, err, "Configure released session too early")
	configured = configureFixture(t, p, rt, cfg)
	noErrors(t, configured.Diagnostics)
	_, err = oldStrategy.Token(context.Background())
	require.ErrorIs(t, err, auth.ErrState, "reconfiguration did not close old session")
	require.NoError(t, oldStore.Close())
	current := p.strategy
	_, err = Protocol6(p).StopProvider(context.Background(), &tfprotov6.StopProviderRequest{})
	require.NoError(t, err)
	_, err = current.Token(context.Background())
	require.ErrorIs(t, err, auth.ErrState, "StopProvider did not close session")
}

func TestProviderRejectsWrongDecodedRole(t *testing.T) {
	for _, role := range []string{"member", "control", ""} {
		t.Run(role, func(t *testing.T) {
			rt := fixtureTransport(t, role, func(w http.ResponseWriter, req *http.Request) {
				assert.Fail(t, "wrong-role credential reached management API")
			})
			p := New()
			t.Cleanup(func() {
				assert.NoError(t, p.Close(), "could not close SDK authentication")
			})
			configured := configureFixture(t, p, rt, providerModel{CRN: types.StringValue(testCRN), AccessKey: types.StringValue("CSAKtestKeyId.testKeySecret")})
			require.True(t, configured.Diagnostics.HasError(), "%v", configured.Diagnostics)
			require.Nil(t, configured.ResourceData)
			require.Nil(t, configured.DataSourceData)
			require.Nil(t, p.strategy)
			require.Nil(t, p.store)
		})
	}
}

func TestProviderDefersAuthorizationToServices(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			rt := fixtureTransport(t, "admin", func(w http.ResponseWriter, req *http.Request) {
				assert.Contains(t, []string{"/api/actors", "/list-clients"}, req.URL.Path, "unexpected administration request")
				http.Error(w, "denied: test-secret-not-a-credential", status)
			})
			p := New()
			t.Cleanup(func() {
				assert.NoError(t, p.Close(), "could not close SDK authentication")
			})
			configured := configureFixture(t, p, rt, providerModel{CRN: types.StringValue(testCRN), AccessKey: types.StringValue("CSAKtestKeyId.testKeySecret")})
			noErrors(t, configured.Diagnostics)
			api, err := clientFromProviderData(configured.ResourceData)
			require.NoError(t, err, "configuration must leave request authorization to the services")
			require.NotNil(t, api)
			for _, tc := range []struct {
				r     resource.Resource
				model any
			}{
				{&actorResource{client: api}, savedActor()},
				{&clientResource{client: api}, savedClient()},
			} {
				before := resourceState(t, tc.r, tc.model)
				read := resource.ReadResponse{State: before}
				tc.r.Read(context.Background(), resource.ReadRequest{State: before}, &read)
				wantError := control.ErrForbidden
				if status == http.StatusUnauthorized {
					wantError = control.ErrAuthentication
				}

				require.True(t, read.Diagnostics.HasError(), "%v", read.Diagnostics)
				require.Equal(t, operationError(wantError), read.Diagnostics[0].Detail())
				require.True(t, read.State.Raw.Equal(before.Raw), "service denial must retain state")
			}
		})
	}
}

func TestKeysetGrantSDKCRUDPreservesOtherGrants(t *testing.T) {
	var mu sync.Mutex
	grants := []string{tenantKeysetID}
	rt := fixtureTransport(t, "admin", func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		switch req.URL.Path {
		case "/list-clients":
			assert.NoError(t, json.NewEncoder(w).Encode([]map[string]any{
				{"id": "44444444-4444-4444-8444-444444444444", "keyset_id": []string{keysetID}},
				{"id": clientID, "name": "existing", "keyset_id": grants},
			}))
		case "/grant-keyset", "/revoke-keyset":
			var input struct {
				ClientID string `json:"client_id"`
				KeysetID string `json:"keyset_id"`
			}
			assert.NoError(t, json.NewDecoder(req.Body).Decode(&input))
			if input.ClientID != clientID || input.KeysetID != keysetID {
				assert.Fail(t, "mutation targeted the wrong pair")
				http.Error(w, "wrong pair", http.StatusBadRequest)

				return
			}

			if req.URL.Path == "/grant-keyset" {
				grants = append(grants, input.KeysetID)
			} else {
				grants = slices.DeleteFunc(grants, func(id string) bool { return id == input.KeysetID })
			}

			_, err := fmt.Fprint(w, `{}`)
			assert.NoError(t, err)
		default:
			assert.Failf(t, "unexpected request", "%s", req.URL.Path)
			http.NotFound(w, req)
		}
	})
	r := &keysetGrantResource{client: fixtureClient(t, rt)}
	plan := resourceState(t, r, keysetGrantModel{ID: types.StringUnknown(), ClientID: types.StringValue(clientID), KeysetID: types.StringValue(keysetID)})
	created := resource.CreateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan(plan)}, &created)
	noErrors(t, created.Diagnostics)
	mu.Lock()
	assert.Equal(t, []string{tenantKeysetID, keysetID}, grants, "creation changed external grants or failed to create the selected grant")
	mu.Unlock()
	imported := resource.ImportStateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: clientID + "/" + keysetID}, &imported)
	noErrors(t, imported.Diagnostics)
	require.True(t, imported.State.Raw.Equal(created.State.Raw), "import did not recover the created pair")
	read := resource.ReadResponse{State: created.State}
	r.Read(context.Background(), resource.ReadRequest{State: created.State}, &read)
	noErrors(t, read.Diagnostics)
	require.True(t, read.State.Raw.Equal(created.State.Raw), "refresh changed the pair identity")
	deleted := resource.DeleteResponse{State: created.State}
	r.Delete(context.Background(), resource.DeleteRequest{State: created.State}, &deleted)
	noErrors(t, deleted.Diagnostics)
	mu.Lock()
	assert.Equal(t, []string{tenantKeysetID}, grants, "deletion did not restore the original external grant inventory")
	mu.Unlock()
}

func TestKeysetSDKCRUDDisablesAndRetains(t *testing.T) {
	var mu sync.Mutex
	var remote *control.Keyset
	unrelated := control.Keyset{ID: tenantKeysetID, Name: "worker-owned", Description: "unchanged", IsDefault: true}
	rt := fixtureTransport(t, "admin", func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		switch req.URL.Path {
		case "/create-keyset":
			var input control.CreateKeysetOptions
			assert.NoError(t, json.NewDecoder(req.Body).Decode(&input))
			assert.Nil(t, input.Client, "keyset resource must not create a client")
			remote = &control.Keyset{ID: keysetID, Name: input.Name, Description: input.Description}
			assert.NoError(t, json.NewEncoder(w).Encode(remote))
		case "/list-keysets":
			var input control.ListKeysetsOptions
			assert.NoError(t, json.NewDecoder(req.Body).Decode(&input))
			keysets := []control.Keyset{unrelated}
			if remote != nil && (input.ShowDisabled || !remote.IsDisabled) {
				keysets = append(keysets, *remote)
			}

			assert.NoError(t, json.NewEncoder(w).Encode(keysets))
		case "/modify-keyset", "/enable-keyset", "/disable-keyset":
			var input struct {
				KeysetID string `json:"keyset_id"`
				control.ModifyKeysetOptions
			}
			assert.NoError(t, json.NewDecoder(req.Body).Decode(&input))
			if remote == nil || input.KeysetID != keysetID {
				assert.Fail(t, "mutation targeted an unrelated keyset")
				http.Error(w, "wrong keyset", http.StatusBadRequest)

				return
			}

			switch req.URL.Path {
			case "/modify-keyset":
				if input.Name != nil {
					remote.Name = *input.Name
				}

				if input.Description != nil {
					remote.Description = *input.Description
				}
			case "/enable-keyset":
				remote.IsDisabled = false
			case "/disable-keyset":
				remote.IsDisabled = true
			}

			_, err := fmt.Fprint(w, `{}`)
			assert.NoError(t, err)
		default:
			assert.Failf(t, "unexpected request", "%s", req.URL.Path)
			http.NotFound(w, req)
		}
	})
	r := &keysetResource{client: fixtureClient(t, rt)}
	plan := resourceState(t, r, keysetModel{ID: types.StringUnknown(), Name: types.StringValue("created"), Description: types.StringValue("original description"), Enabled: types.BoolValue(false), IsDefault: types.BoolUnknown()})
	created := resource.CreateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan(plan)}, &created)
	noErrors(t, created.Diagnostics)
	var saved keysetModel
	noErrors(t, created.State.Get(context.Background(), &saved))
	require.Equal(t, keysetID, saved.ID.ValueString())
	require.False(t, saved.Enabled.ValueBool())
	require.False(t, saved.IsDefault.ValueBool())
	plan = resourceState(t, r, keysetModel{ID: types.StringValue(keysetID), Name: types.StringValue("renamed"), Description: types.StringValue("original description"), Enabled: types.BoolValue(true), IsDefault: types.BoolUnknown()})
	updated := resource.UpdateResponse{State: created.State}
	r.Update(context.Background(), resource.UpdateRequest{State: created.State, Plan: tfsdk.Plan(plan)}, &updated)
	noErrors(t, updated.Diagnostics)
	noErrors(t, updated.State.Get(context.Background(), &saved))
	require.Equal(t, keysetID, saved.ID.ValueString())
	require.Equal(t, "renamed", saved.Name.ValueString())
	require.Equal(t, "original description", saved.Description.ValueString())
	require.True(t, saved.Enabled.ValueBool())
	read := resource.ReadResponse{State: updated.State}
	r.Read(context.Background(), resource.ReadRequest{State: updated.State}, &read)
	noErrors(t, read.Diagnostics)
	require.True(t, read.State.Raw.Equal(updated.State.Raw), "refresh changed the persisted keyset")
	deleted := resource.DeleteResponse{State: updated.State}
	r.Delete(context.Background(), resource.DeleteRequest{State: updated.State}, &deleted)
	noErrors(t, deleted.Diagnostics)
	require.Equal(t, 1, deleted.Diagnostics.WarningsCount(), "destroy must warn that the keyset remains remotely")
	mu.Lock()
	if assert.NotNil(t, remote, "destroy must retain the disabled keyset") {
		assert.Equal(t, keysetID, remote.ID)
		assert.True(t, remote.IsDisabled)
		assert.Equal(t, "renamed", remote.Name)
	}

	assert.False(t, unrelated.IsDisabled)
	mu.Unlock()
	imported := resource.ImportStateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: keysetID}, &imported)
	noErrors(t, imported.Diagnostics)
	noErrors(t, imported.State.Get(context.Background(), &saved))
	require.Equal(t, keysetID, saved.ID.ValueString())
	require.Equal(t, "renamed", saved.Name.ValueString())
	require.False(t, saved.Enabled.ValueBool())
}
