package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/manage"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigureRejectsUnknownAndEmptyInputs(t *testing.T) {
	t.Setenv("CS_CLIENT_ACCESS_KEY", "CSAKenvironment.secret")
	t.Setenv("CS_WORKSPACE_CRN", testCRN)
	t.Setenv("CS_CONTROL_ACCESS_KEY", "")
	t.Setenv("CIPHERSTASH_ACCESS_KEY", "")
	for _, tc := range []struct {
		name    string
		config  providerModel
		summary string
	}{
		{"unknown key", authConfig(types.StringValue("crn:ap-southeast-2.aws:7RVRVMCTYKZC5TU7"), types.StringUnknown()), "Unknown access key"},
		{"empty key", authConfig(types.StringValue(testCRN), types.StringValue("")), "Client access key required"},
		{"malformed key", authConfig(types.StringValue(testCRN), types.StringValue("selected-invalid-key-secret")), "Invalid access key"},
		{"unknown crn", authConfig(types.StringUnknown(), types.StringNull()), "Workspace CRN required"},
		{"empty crn", authConfig(types.StringValue(""), types.StringNull()), "Workspace CRN required"},
		{"malformed crn", authConfig(types.StringValue("invalid-crn"), types.StringNull()), "Invalid workspace CRN"},
		{"missing environment crn", authConfig(types.StringNull(), types.StringNull()), "Workspace CRN required"},
		{"malformed environment crn", authConfig(types.StringNull(), types.StringNull()), "Invalid workspace CRN"},
		{"missing environment key", authConfig(types.StringValue(testCRN), types.StringNull()), "Client access key required"},
		{"malformed environment key", authConfig(types.StringValue(testCRN), types.StringNull()), "Invalid access key"},
		{"legacy control environment key", authConfig(types.StringValue(testCRN), types.StringNull()), "Client access key required"},
		{"legacy cipherstash environment key", authConfig(types.StringValue(testCRN), types.StringNull()), "Client access key required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			switch tc.name {
			case "missing environment crn":
				t.Setenv("CS_WORKSPACE_CRN", "")
			case "malformed environment crn":
				t.Setenv("CS_WORKSPACE_CRN", "invalid-crn")
			case "missing environment key":
				t.Setenv("CS_CLIENT_ACCESS_KEY", "")
			case "malformed environment key":
				t.Setenv("CS_CLIENT_ACCESS_KEY", "selected-invalid-key-secret")
				t.Setenv("CS_CONTROL_ACCESS_KEY", "CSAKlegacy.secret")
				t.Setenv("CIPHERSTASH_ACCESS_KEY", "CSAKlegacy.secret")
			case "legacy control environment key":
				t.Setenv("CS_CLIENT_ACCESS_KEY", "")
				t.Setenv("CS_CONTROL_ACCESS_KEY", "CSAKlegacy.secret")
			case "legacy cipherstash environment key":
				t.Setenv("CS_CLIENT_ACCESS_KEY", "")
				t.Setenv("CIPHERSTASH_ACCESS_KEY", "CSAKlegacy.secret")
			}

			p := New()
			t.Cleanup(p.Close)
			resp := configureFixture(t, p, roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Error("invalid configuration attempted authentication")
				return nil, http.ErrNotSupported
			}), tc.config)
			require.True(t, resp.Diagnostics.HasError(), "unexpected configuration result: %v", resp.Diagnostics)
			require.Equal(t, tc.summary, resp.Diagnostics[0].Summary())
			require.NotContains(t, resp.Diagnostics[0].Detail(), "selected-invalid-key-secret")
			require.Nil(t, resp.ResourceData)
		})
	}
}

func TestConfigureDatabaseOnlyNeverAuthenticates(t *testing.T) {
	t.Setenv("CS_CLIENT_ACCESS_KEY", "CSAKenvironment.secret")
	t.Setenv("CS_WORKSPACE_CRN", testCRN)
	p := New()
	t.Cleanup(p.Close)
	cfg := providerModel{
		Auth: types.ObjectNull(authAttributeTypes),
		Database: types.ObjectValueMust(databaseAttributeTypes, map[string]attr.Value{
			"host": types.StringValue("db.invalid"), "port": types.Int64Null(), "username": types.StringNull(),
			"password": types.StringNull(), "sslmode": types.StringNull(), "sslrootcert": types.StringNull(),
		}),
	}
	resp := configureFixture(t, p, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("database-only configuration contacted CipherStash")
		return nil, http.ErrNotSupported
	}), cfg)
	require.False(t, resp.Diagnostics.HasError(), "unexpected configuration result: %v", resp.Diagnostics)

	_, err := clientFromProviderData(resp.ResourceData)
	require.ErrorIs(t, err, errNoAuth)
	database, err := databaseFromProviderData(resp.ResourceData)
	require.NoError(t, err)
	require.NotNil(t, database)
}

func TestProtocolSchemaAndStop(t *testing.T) {
	p := New()
	server := Protocol6(p)
	resp, err := server.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	require.NoError(t, err)
	for _, d := range resp.Diagnostics {
		require.NotEqual(t, tfprotov6.DiagnosticSeverityError, d.Severity, "%s: %s", d.Summary, d.Detail)
	}

	require.Len(t, resp.ResourceSchemas, 5)
	require.NotNil(t, resp.ResourceSchemas["cipherstash_cts_actor"])
	require.NotNil(t, resp.ResourceSchemas["cipherstash_zerokms_client"])
	require.NotNil(t, resp.ResourceSchemas["cipherstash_zerokms_keyset"])
	require.NotNil(t, resp.ResourceSchemas["cipherstash_zerokms_keyset_grant"])
	require.NotNil(t, resp.ResourceSchemas["cipherstash_eql_v4"])
	require.Len(t, resp.DataSourceSchemas, 1)
	require.NotNil(t, resp.DataSourceSchemas["cipherstash_zerokms_client"])
	for range 2 {
		_, err := server.StopProvider(context.Background(), &tfprotov6.StopProviderRequest{})
		require.NoError(t, err)
	}

	p.Close()
}

func TestProviderCredentialPrecedence(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "null uses environment", true: "explicit overrides environment"}[explicit], func(t *testing.T) {
			t.Setenv("CS_CLIENT_ACCESS_KEY", "CSAKenvironment.secret")
			t.Setenv("CS_CONTROL_ACCESS_KEY", "CSAKignored-control.secret")
			t.Setenv("CIPHERSTASH_ACCESS_KEY", "CSAKignored-legacy.secret")
			t.Setenv("CS_WORKSPACE_CRN", testCRN)
			t.Setenv("CS_CLIENT_ID", "unused-application-client")
			crn := types.StringNull()
			key, want := types.StringNull(), "CSAKenvironment.secret"
			if explicit {
				key, want = types.StringValue("CSAKexplicit.secret"), "CSAKexplicit.secret"
				crn = types.StringValue(testCRN)
				t.Setenv("CS_WORKSPACE_CRN", "invalid-crn-must-not-override-explicit-value")
			}

			f := newServiceFixture(t)
			base := fixtureTransport(t, "admin", f.ServeHTTP)
			observed := make(chan string, 1)
			rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/api/authorise" {
					body, err := io.ReadAll(req.Body)
					if err != nil {
						return nil, err
					}

					if err := req.Body.Close(); err != nil {
						return nil, err
					}

					req.Body = io.NopCloser(bytes.NewReader(body))
					var payload struct {
						AccessKey string `json:"accessKey"`
					}
					if err := json.Unmarshal(body, &payload); !assert.NoError(t, err) {
						return nil, err
					}

					select {
					case observed <- payload.AccessKey:
					default:
						assert.Fail(t, "unexpected additional token exchange")
					}
				}

				return base.RoundTrip(req)
			})
			p := New()
			t.Cleanup(p.Close)
			configured := configureFixture(t, p, rt, authConfig(crn, key))
			noErrors(t, configured.Diagnostics)
			select {
			case got := <-observed:
				require.Equal(t, want, got, "token exchange used the wrong credential source")
			default:
				require.FailNow(t, "provider did not authenticate")
			}
		})
	}
}

func TestProviderInstancesKeepSeparateAuthentication(t *testing.T) {
	f := newServiceFixture(t)
	f.clients = []manage.ZeroKMSClient{{ID: clientID, Name: "application"}}
	rt := fixtureTransport(t, "admin", f.ServeHTTP, func(claims map[string]any) {
		claims["exp"] = time.Now().Add(30 * time.Second).Unix()
	})
	// Short-lived tokens force refresh to exercise each owner's lifetime.
	// They share the process-default HTTP transport, as they do in production.
	left, right := New(), New()
	for _, p := range []*Provider{left, right} {
		t.Cleanup(p.Close)
	}

	cfg := authConfig(types.StringValue(testCRN), types.StringValue("CSAKtestKeyId.testKeySecret"))
	l := configureFixture(t, left, rt, cfg)
	r := configureFixture(t, right, rt, cfg)
	noErrors(t, l.Diagnostics)
	noErrors(t, r.Diagnostics)
	for _, configured := range []provider.ConfigureResponse{l, r} {
		api, err := clientFromProviderData(configured.ResourceData)
		require.NoError(t, err)
		clients, err := api.ListZeroKMSClients(context.Background(), manage.ListZeroKMSClientsOptions{})
		require.NoError(t, err)
		require.Len(t, clients, 1)
		require.Equal(t, clientID, clients[0].ID)
	}

	_, err := Protocol6(left).StopProvider(context.Background(), &tfprotov6.StopProviderRequest{})
	require.NoError(t, err)
	closed, err := clientFromProviderData(l.ResourceData)
	require.NoError(t, err)
	_, err = closed.ListZeroKMSClients(context.Background(), manage.ListZeroKMSClientsOptions{})
	require.ErrorIs(t, err, context.Canceled, "stopped provider still refreshes tokens")
	api, err := clientFromProviderData(r.ResourceData)
	require.NoError(t, err)
	clients, err := api.ListZeroKMSClients(context.Background(), manage.ListZeroKMSClientsOptions{})
	require.NoError(t, err, "stopping one provider closed the other session")
	require.Len(t, clients, 1)
	require.Equal(t, clientID, clients[0].ID)
}

func TestProviderReadCancellationRetainsState(t *testing.T) {
	f := newServiceFixture(t)
	base := fixtureTransport(t, "admin", f.ServeHTTP)
	entered := make(chan struct{}, 1)
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/list-clients" {
			return base.RoundTrip(req)
		}

		entered <- struct{}{}
		<-req.Context().Done()

		return nil, req.Context().Err()
	})
	p := New()
	t.Cleanup(p.Close)
	configured := configureFixture(t, p, rt, authConfig(types.StringValue(testCRN), types.StringValue("CSAKtestKeyId.testKeySecret")))
	noErrors(t, configured.Diagnostics)
	api, err := clientFromProviderData(configured.ResourceData)
	require.NoError(t, err)
	r := &clientResource{client: api}
	before := resourceState(t, r, savedClient())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan resource.ReadResponse, 1)
	go func() {
		resp := resource.ReadResponse{State: before}
		r.Read(ctx, resource.ReadRequest{State: before}, &resp)
		done <- resp
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "read never reached the blocked transport")
	}

	cancel()
	select {
	case resp := <-done:
		require.True(t, resp.Diagnostics.HasError(), "cancelled read reported success: %v", resp.Diagnostics)
		require.True(t, resp.State.Raw.Equal(before.Raw), "cancelled read forgot its client")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "request cancellation did not release the blocked read")
	}
}
