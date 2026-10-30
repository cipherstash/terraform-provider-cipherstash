package manage_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/auth"
	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/ctstest"
	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/useragent"
	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/manage"
)

const zeroKMSHost = "kms.example"

// newTokenSource authenticates against a fake CTS that issues tokens for zeroKMSURL.
func newTokenSource(t *testing.T, zeroKMSURL string) (oauth2.TokenSource, string) {
	t.Helper()
	var bearer string
	cts := ctstest.New(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": bearer})
	})
	claims := ctstest.Claims()
	claims["role_set"] = []string{"admin"}
	claims["services"] = map[string]string{"zerokms": zeroKMSURL}
	bearer = cts.Sign(t, claims)

	return adminTokenSource(t, cts.Transport()), bearer
}

func adminTokenSource(t *testing.T, transport http.RoundTripper) oauth2.TokenSource {
	t.Helper()
	key, err := auth.ParseAdminAccessKey(ctstest.AccessKey)
	require.NoError(t, err)
	tokens, err := auth.NewTokenSource(t.Context(), workspaceCRN(t), key, auth.WithTransport(transport))
	require.NoError(t, err)

	return tokens
}

func workspaceCRN(t *testing.T) auth.CRN {
	t.Helper()
	crn, err := auth.ParseCRN(ctstest.CRN)
	require.NoError(t, err)

	return crn
}

// newClient serves CTS administration at the real CTS host and ZeroKMS at
// zeroKMSHost below /zerokms, on one test server. The handler sees ZeroKMS
// paths without that prefix.
func newClient(t *testing.T, handler http.HandlerFunc) *manage.Client {
	t.Helper()
	var bearer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+bearer || r.Header.Get("User-Agent") != useragent.Value {
			t.Errorf("%s %s: wrong credentials or User-Agent", r.Method, r.URL.Path)
		}

		switch r.Host {
		case zeroKMSHost:
			path, ok := strings.CutPrefix(r.URL.Path, "/zerokms/")
			if !ok {
				t.Errorf("%s %s: ZeroKMS request outside the endpoint path", r.Method, r.URL.Path)
			}

			r.URL.Path = "/" + path
		case ctstest.Host:
			if r.Header.Get("X-Cs-Workspace-Id") != ctstest.Workspace {
				t.Errorf("%s %s: CTS request without the workspace header", r.Method, r.URL.Path)
			}
		default:
			t.Errorf("%s %s: request for unexpected host %s", r.Method, r.URL.Path, r.Host)
		}

		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	// No trailing slash: operations must still resolve below the endpoint path.
	tokens, issued := newTokenSource(t, "https://"+zeroKMSHost+"/zerokms")
	bearer = issued
	client, err := manage.NewClient(workspaceCRN(t), tokens, manage.WithTransport(ctstest.Redirect(t, server, ctstest.Host, zeroKMSHost)))
	require.NoError(t, err)

	return client
}

func decode(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var body map[string]any
	assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))

	return body
}

func TestNewClient(t *testing.T) {
	var tokenCalls atomic.Int32
	counting := oauth2.TokenSource(tokenSourceFunc(func() (*oauth2.Token, error) {
		tokenCalls.Add(1)

		return nil, errors.New("unexpected token request")
	}))
	for name, construct := range map[string]func() (*manage.Client, error){
		"zero CRN":   func() (*manage.Client, error) { return manage.NewClient(auth.CRN{}, counting) },
		"nil tokens": func() (*manage.Client, error) { return manage.NewClient(workspaceCRN(t), nil) },
		"nil transport": func() (*manage.Client, error) {
			return manage.NewClient(workspaceCRN(t), counting, manage.WithTransport(nil))
		},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := construct()
			require.ErrorIs(t, err, manage.ErrConfig)
			assert.Nil(t, client)
		})
	}

	_, err := manage.NewClient(workspaceCRN(t), counting)
	require.NoError(t, err)
	assert.Zero(t, tokenCalls.Load(), "construction must not acquire a token")

	// Authentication failures keep auth's error identity and send no administration request.
	cts := ctstest.New(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { calls.Add(1) }))
	t.Cleanup(server.Close)
	client, err := manage.NewClient(workspaceCRN(t), adminTokenSource(t, cts.Transport()),
		manage.WithTransport(ctstest.Redirect(t, server, ctstest.Host)))
	require.NoError(t, err)
	err = client.EnableKeyset(t.Context(), "keyset-1")
	require.ErrorIs(t, err, manage.ErrAuthentication)
	require.ErrorIs(t, err, auth.ErrAuthentication)
	_, err = client.ListAccessKeys(t.Context())
	require.ErrorIs(t, err, manage.ErrAuthentication)
	assert.Zero(t, calls.Load())
}

type tokenSourceFunc func() (*oauth2.Token, error)

func (f tokenSourceFunc) Token() (*oauth2.Token, error) { return f() }

func TestActorAndClientContractsAndOneShotSecrets(t *testing.T) {
	client := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /api/actors":
			assert.Equal(t, map[string]any{"name": "worker", "kind": "app", "role": "control", "tokenExpiry": float64(3600)}, decode(t, r))
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprint(w, `{"actorId":"actor-1","name":"worker","kind":"app","role":"control","accessKey":"CSAKone.secret"}`)
		case "GET /api/actors":
			assert.Equal(t, "a+/=", r.URL.Query().Get("cursor"))
			assert.Equal(t, "7", r.URL.Query().Get("limit"))
			_, _ = fmt.Fprint(w, `{"items":[{"actorId":"actor-1","name":"worker","kind":"app","createdAt":"today"}],"nextCursor":"second"}`)
		case "GET /api/access-keys":
			_, _ = fmt.Fprint(w, `[{"keyId":"key-1","keyName":"worker","workspaceId":"GXT2N5F4X2SKVEJX","role":"control","createdAt":"today","lastUsedAt":null}]`)
		case "DELETE /api/actors/actor-1":
			_, _ = fmt.Fprint(w, `{}`)
		case "POST /create-client":
			assert.Equal(t, map[string]any{"name": "app", "description": "test", "keyset_id": "keyset-1"}, decode(t, r))
			_, _ = fmt.Fprint(w, `{"id":"client-1","name":"app","description":"test","dataset_id":"keyset-1","client_key":"encoded-client-key"}`)
		case "POST /list-clients":
			assert.Equal(t, map[string]any{"keyset_id": map[string]any{"Uuid": "keyset-1"}}, decode(t, r))
			_, _ = fmt.Fprint(w, `[{"id":"00000000-0000-4000-8000-000000000001","name":"single","description":"","keyset_id":"00000000-0000-4000-8000-000000000011"},{"id":"00000000-0000-4000-8000-000000000002","name":"multiple","description":"","keyset_id":["00000000-0000-4000-8000-000000000012","00000000-0000-4000-8000-000000000011"]}]`)
		case "POST /delete-client":
			assert.Equal(t, map[string]any{"client_id": "client-1"}, decode(t, r))
			_, _ = fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected operation %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})
	ctx := t.Context()
	expiry := int64(3600)
	actor, err := client.CreateActor(ctx, manage.CreateActorOptions{Name: "worker", Kind: "app", Role: "control", TokenExpiry: &expiry})
	require.NoError(t, err)
	assert.Equal(t, manage.Actor{ID: "actor-1", Name: "worker", Kind: "app"}, actor.Actor)
	assert.Equal(t, manage.Role("control"), actor.Role)
	copied := *actor
	key, err := actor.ExportAccessKey()
	require.NoError(t, err)
	assert.Equal(t, "CSAKone.secret", string(key))
	_, err = copied.ExportAccessKey()
	require.ErrorIs(t, err, manage.ErrSecretConsumed, "copies share one extraction right")

	page, err := client.ListActors(ctx, manage.ListActorsOptions{Limit: 7, Cursor: "a+/="})
	require.NoError(t, err)
	assert.Equal(t, manage.ActorPage{Items: []manage.Actor{{ID: "actor-1", Name: "worker", Kind: "app", CreatedAt: "today"}}, NextCursor: "second"}, page)
	keys, err := client.ListAccessKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, []manage.AccessKeyMetadata{{ID: "key-1", Name: "worker", WorkspaceID: ctstest.Workspace, Role: "control", CreatedAt: "today"}}, keys)

	created, err := client.CreateClient(ctx, manage.CreateClientOptions{Name: "app", Description: "test", KeysetID: "keyset-1"})
	require.NoError(t, err)
	assert.Equal(t, manage.EncryptionClient{ID: "client-1", Name: "app", Description: "test", KeysetIDs: []string{"keyset-1"}}, created.EncryptionClient)
	assert.Equal(t, "keyset-1", created.KeysetID)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x"} {
		assert.Equal(t, "manage.CreatedClient(***)", fmt.Sprintf(verb, created), verb)
		assert.Equal(t, "manage.CreatedClient(***)", fmt.Sprintf(verb, *created), verb)
		assert.Equal(t, "manage.CreatedActor(***)", fmt.Sprintf(verb, actor), verb)
		assert.Equal(t, "manage.CreatedActor(***)", fmt.Sprintf(verb, *actor), verb)
	}

	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			copied := *created
			exported, err := copied.ExportClientKey()
			if err != nil {
				assert.ErrorIs(t, err, manage.ErrSecretConsumed)

				return
			}

			wins.Add(1)
			assert.Equal(t, "encoded-client-key", string(exported))
		})
	}

	wg.Wait()
	assert.Equal(t, int32(1), wins.Load(), "secret export must be exclusive")

	listed, err := client.ListClients(ctx, manage.ListClientsOptions{KeysetID: "keyset-1"})
	require.NoError(t, err)
	assert.Equal(t, []manage.EncryptionClient{
		{ID: "00000000-0000-4000-8000-000000000001", Name: "single", KeysetIDs: []string{"00000000-0000-4000-8000-000000000011"}},
		{ID: "00000000-0000-4000-8000-000000000002", Name: "multiple", KeysetIDs: []string{"00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000011"}},
	}, listed)
	require.NoError(t, client.DeleteActor(ctx, actor.ID))
	require.NoError(t, client.DeleteClient(ctx, created.ID))
}

func TestDefaultsAreOmittedFromRequests(t *testing.T) {
	bodies := make(map[string]map[string]any)
	client := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		bodies[r.URL.Path] = decode(t, r)
		switch r.URL.Path {
		case "/api/actors":
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprint(w, `{"actorId":"actor-1","name":"worker","kind":"app","role":"member","accessKey":"CSAKone.secret"}`)
		case "/create-client":
			_, _ = fmt.Fprint(w, `{"id":"client-1","name":"app","description":"","dataset_id":"keyset-1","client_key":"encoded-key"}`)
		case "/create-keyset":
			_, _ = fmt.Fprint(w, `{"id":"keyset-1","name":"tenant","description":"","is_disabled":false}`)
		default:
			_, _ = fmt.Fprint(w, `[]`)
		}
	})
	ctx := t.Context()
	actor, err := client.CreateActor(ctx, manage.CreateActorOptions{Name: "worker", Kind: "app"})
	require.NoError(t, err)
	actor.Wipe()
	created, err := client.CreateClient(ctx, manage.CreateClientOptions{Name: "app"})
	require.NoError(t, err)
	created.Wipe()
	_, err = client.CreateKeyset(ctx, manage.CreateKeysetOptions{Name: "tenant"})
	require.NoError(t, err)
	_, err = client.ListKeysets(ctx, manage.ListKeysetsOptions{})
	require.NoError(t, err)

	// Omitted fields select the service defaults: role, default keyset, no client, enabled keysets only.
	assert.Equal(t, map[string]map[string]any{
		"/api/actors":    {"name": "worker", "kind": "app"},
		"/create-client": {"name": "app", "description": ""},
		"/create-keyset": {"name": "tenant", "description": ""},
		"/list-keysets":  {},
	}, bodies)
}

func TestWipe(t *testing.T) {
	client := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"id":"client-1","name":"app","description":"","dataset_id":"keyset-1","client_key":"encoded-client-key"}`)
	})
	created, err := client.CreateClient(t.Context(), manage.CreateClientOptions{Name: "app"})
	require.NoError(t, err)
	created.Wipe()
	created.Wipe()
	_, err = created.ExportClientKey()
	require.ErrorIs(t, err, manage.ErrSecretConsumed)

	var nilClient *manage.CreatedClient
	var nilActor *manage.CreatedActor
	nilClient.Wipe()
	nilActor.Wipe()
	_, err = nilClient.ExportClientKey()
	require.ErrorIs(t, err, manage.ErrSecretConsumed)
	_, err = nilActor.ExportAccessKey()
	require.ErrorIs(t, err, manage.ErrSecretConsumed)
}

func TestKeysetContracts(t *testing.T) {
	expected := map[string]string{
		"/create-keyset":  `{"name":"tenant","description":"tenant keys","client":{"name":"app","client_type":"device"}}`,
		"/list-keysets":   `{"show_disabled":true}`,
		"/modify-keyset":  `{"keyset_id":"keyset-1","description":""}`,
		"/enable-keyset":  `{"keyset_id":"keyset-1"}`,
		"/disable-keyset": `{"keyset_id":"keyset-1"}`,
		"/grant-keyset":   `{"keyset_id":"keyset-1","client_id":"client-2"}`,
		"/revoke-keyset":  `{"keyset_id":"keyset-1","client_id":"client-2"}`,
	}
	var calls []string
	client := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		want, ok := expected[r.URL.Path]
		if !assert.True(t, ok, "unexpected path %s", r.URL.Path) || !assert.Equal(t, http.MethodPost, r.Method) {
			return
		}

		var got any
		if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&got)) {
			return
		}

		assert.JSONEq(t, want, mustJSON(t, got), r.URL.Path)
		switch r.URL.Path {
		case "/create-keyset":
			_, _ = fmt.Fprint(w, `{"id":"keyset-1","name":"tenant","description":"tenant keys","is_disabled":false,"client":{"id":"client-2","client_key":"encoded-key"}}`)
		case "/list-keysets":
			_, _ = fmt.Fprint(w, `[{"id":"00000000-0000-4000-8000-000000000011","name":"tenant","description":"tenant keys","is_disabled":true,"is_default":false},{"id":"00000000-0000-4000-8000-000000000012","name":"default","description":"","is_disabled":false,"is_default":true}]`)
		default:
			_, _ = fmt.Fprint(w, `{}`)
		}
	})
	ctx := t.Context()
	created, err := client.CreateKeyset(ctx, manage.CreateKeysetOptions{
		Name: "tenant", Description: "tenant keys",
		Client: &manage.CreateKeysetClientOptions{Name: "app", ClientType: "device"},
	})
	require.NoError(t, err)
	assert.Equal(t, manage.Keyset{ID: "keyset-1", Name: "tenant", Description: "tenant keys"}, created.Keyset)
	require.NotNil(t, created.Client)
	assert.Equal(t, manage.EncryptionClient{ID: "client-2", Name: "app", KeysetIDs: []string{"keyset-1"}}, created.Client.EncryptionClient)
	assert.Equal(t, "keyset-1", created.Client.KeysetID)
	key, err := created.Client.ExportClientKey()
	require.NoError(t, err)
	assert.Equal(t, "encoded-key", string(key))

	listed, err := client.ListKeysets(ctx, manage.ListKeysetsOptions{ShowDisabled: true})
	require.NoError(t, err)
	assert.Equal(t, []manage.Keyset{
		{ID: "00000000-0000-4000-8000-000000000011", Name: "tenant", Description: "tenant keys", IsDisabled: true},
		{ID: "00000000-0000-4000-8000-000000000012", Name: "default", IsDefault: true},
	}, listed)

	empty := ""
	require.NoError(t, client.ModifyKeyset(ctx, "keyset-1", manage.ModifyKeysetOptions{Description: &empty}))
	require.NoError(t, client.EnableKeyset(ctx, "keyset-1"))
	require.NoError(t, client.DisableKeyset(ctx, "keyset-1"))
	require.NoError(t, client.GrantKeyset(ctx, "keyset-1", "client-2"))
	require.NoError(t, client.RevokeKeyset(ctx, "keyset-1", "client-2"))
	assert.Len(t, calls, len(expected))
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)

	return string(encoded)
}

func TestFailuresDoNotLeakRetryOrRedirect(t *testing.T) {
	var calls atomic.Int32
	var status atomic.Int32
	client := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "/redirected")
		w.WriteHeader(int(status.Load()))
		_, _ = fmt.Fprint(w, `{"error":"CSAKsecret.must-not-leak"}`)
	})
	for _, tc := range []struct {
		status int
		target error
	}{
		{http.StatusBadRequest, manage.ErrResponse},
		{http.StatusUnauthorized, manage.ErrAuthentication},
		{http.StatusForbidden, manage.ErrForbidden},
		{http.StatusNotFound, manage.ErrNotFound},
		{http.StatusConflict, manage.ErrConflict},
		{http.StatusInternalServerError, manage.ErrResponse},
		{http.StatusTemporaryRedirect, manage.ErrResponse},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			status.Store(int32(tc.status))
			before := calls.Load()
			err := client.GrantKeyset(t.Context(), "keyset-1", "client-1")
			require.ErrorIs(t, err, tc.target)
			assert.NotContains(t, err.Error(), "must-not-leak")
			var httpErr *manage.HTTPError
			require.ErrorAs(t, err, &httpErr)
			assert.Equal(t, manage.HTTPError{Service: "zerokms", StatusCode: tc.status}, *httpErr)
			assert.Equal(t, before+1, calls.Load(), "write retried or redirected")

			err = client.DeleteActor(t.Context(), "actor-1")
			require.ErrorAs(t, err, &httpErr)
			assert.Equal(t, manage.HTTPError{Service: "cts", StatusCode: tc.status}, *httpErr)
		})
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := calls.Load()
	require.ErrorIs(t, client.DeleteClient(ctx, "client-1"), context.Canceled)
	assert.Equal(t, before, calls.Load(), "cancelled request reached the service")
}

func TestTransportFailureIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	client := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		conn, _, err := http.NewResponseController(w).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	})
	_, err := client.CreateClient(t.Context(), manage.CreateClientOptions{Name: "app"})
	require.ErrorIs(t, err, manage.ErrTransport)
	assert.Equal(t, int32(1), calls.Load())
}

func TestInvalidInventoriesAreNotEmptyInventories(t *testing.T) {
	var body atomic.Value
	client := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, body.Load().(string))
	})
	ctx := t.Context()
	for _, response := range []string{"null", "{}", "[null]", "[{}]", "["} {
		body.Store(response)
		_, err := client.ListKeysets(ctx, manage.ListKeysetsOptions{})
		require.ErrorIs(t, err, manage.ErrResponse, "keysets %.20q", response)
		_, err = client.ListClients(ctx, manage.ListClientsOptions{})
		require.ErrorIs(t, err, manage.ErrResponse, "clients %.20q", response)
		_, err = client.ListAccessKeys(ctx)
		require.ErrorIs(t, err, manage.ErrResponse, "access keys %.20q", response)
	}

	for _, response := range []string{`null`, `{}`, `{"items":null}`, `{"items":[{}]}`} {
		body.Store(response)
		_, err := client.ListActors(ctx, manage.ListActorsOptions{})
		require.ErrorIs(t, err, manage.ErrResponse, response)
	}

	for _, state := range []string{``, `,"is_disabled":null`} {
		body.Store(`[{"id":"00000000-0000-4000-8000-000000000011","name":"tenant","description":""` + state + `}]`)
		_, err := client.ListKeysets(ctx, manage.ListKeysetsOptions{})
		require.ErrorIs(t, err, manage.ErrResponse, state)
	}

	body.Store(`[{"id":"00000000-0000-4000-8000-000000000001","description":"","keyset_id":[]}]`)
	_, err := client.ListClients(ctx, manage.ListClientsOptions{})
	require.ErrorIs(t, err, manage.ErrResponse, "client without a name")
	for _, association := range []string{`null`, `""`, `[null]`, `[""]`, `{}`} {
		body.Store(`[{"id":"00000000-0000-4000-8000-000000000001","name":"app","description":"","keyset_id":` + association + `}]`)
		_, err := client.ListClients(ctx, manage.ListClientsOptions{})
		require.ErrorIs(t, err, manage.ErrResponse, association)
	}

	// Empty inventories, omitted is_default and ungranted clients remain valid.
	body.Store(`[]`)
	keysets, err := client.ListKeysets(ctx, manage.ListKeysetsOptions{})
	require.NoError(t, err)
	assert.Empty(t, keysets)
	body.Store(`{"items":[]}`)
	page, err := client.ListActors(ctx, manage.ListActorsOptions{})
	require.NoError(t, err)
	assert.Equal(t, manage.ActorPage{Items: []manage.Actor{}}, page)
	body.Store(`[{"id":"00000000-0000-4000-8000-000000000011","name":"tenant","description":"","is_disabled":false,"extra":{"id":"ignored","keyset_id":null}}]`)
	keysets, err = client.ListKeysets(ctx, manage.ListKeysetsOptions{})
	require.NoError(t, err)
	assert.Equal(t, []manage.Keyset{{ID: "00000000-0000-4000-8000-000000000011", Name: "tenant"}}, keysets)
	body.Store(`[{"id":"00000000-0000-4000-8000-000000000001","name":"app","description":"","keyset_id":[],"extra":{"id":"ignored","keyset_id":null}}]`)
	clients, err := client.ListClients(ctx, manage.ListClientsOptions{})
	require.NoError(t, err)
	assert.Equal(t, []manage.EncryptionClient{{ID: "00000000-0000-4000-8000-000000000001", Name: "app", KeysetIDs: []string{}}}, clients)
}

func TestIncompleteCreationResponsesFailWithoutRetry(t *testing.T) {
	var body atomic.Value
	var calls atomic.Int32
	client := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/api/actors" {
			w.WriteHeader(http.StatusCreated)
		}

		_, _ = fmt.Fprint(w, body.Load().(string))
	})
	ctx := t.Context()
	for _, tc := range []struct {
		name     string
		valid    string
		required []string
		call     func() error
	}{
		{
			"actor", `{"actorId":"actor-1","name":"worker","kind":"app","role":"member","accessKey":"CSAKone.secret"}`,
			[]string{"actorId", "name", "kind", "role", "accessKey"},
			func() error {
				out, err := client.CreateActor(ctx, manage.CreateActorOptions{Name: "worker", Kind: "app"})
				out.Wipe()

				return err
			},
		},
		{
			"client", `{"id":"client-1","name":"app","description":"","dataset_id":"keyset-1","client_key":"encoded-key"}`,
			[]string{"id", "name", "description", "dataset_id", "client_key"},
			func() error {
				out, err := client.CreateClient(ctx, manage.CreateClientOptions{Name: "app"})
				out.Wipe()

				return err
			},
		},
		{
			"keyset", `{"id":"keyset-1","name":"tenant","description":"","is_disabled":false}`,
			[]string{"id", "name", "description", "is_disabled"},
			func() error {
				_, err := client.CreateKeyset(ctx, manage.CreateKeysetOptions{Name: "tenant"})

				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body.Store(tc.valid)
			require.NoError(t, tc.call())
			for _, field := range tc.required {
				for _, missing := range []bool{true, false} {
					var response map[string]any
					require.NoError(t, json.Unmarshal([]byte(tc.valid), &response))
					if missing {
						delete(response, field)
					} else {
						response[field] = nil
					}

					body.Store(mustJSON(t, response))
					before := calls.Load()
					require.ErrorIs(t, tc.call(), manage.ErrResponse, "%s missing=%v", field, missing)
					assert.Equal(t, before+1, calls.Load(), "creation retried")
				}
			}
		})
	}

	for _, nested := range []string{``, `,"client":null`, `,"client":{}`, `,"client":{"id":"client-1"}`, `,"client":{"client_key":"encoded-key"}`} {
		body.Store(`{"id":"keyset-1","name":"tenant","description":"","is_disabled":false` + nested + `}`)
		before := calls.Load()
		_, err := client.CreateKeyset(ctx, manage.CreateKeysetOptions{
			Name: "tenant", Client: &manage.CreateKeysetClientOptions{Name: "app", ClientType: "device"},
		})
		require.ErrorIs(t, err, manage.ErrResponse, nested)
		assert.Equal(t, before+1, calls.Load(), "keyset creation retried")
	}
}

func TestRefreshedBearerAndEndpointStayPaired(t *testing.T) {
	var endpoints [2]*httptest.Server
	var issued [2]string
	var requests [2]atomic.Int32
	for i := range endpoints {
		endpoints[i] = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests[i].Add(1)
			assert.Equal(t, "Bearer "+issued[i], r.Header.Get("Authorization"), "endpoint %d", i)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `[{"id":"00000000-0000-4000-8000-%012d","name":"tenant","description":"","is_disabled":false}]`, i)
		}))
		t.Cleanup(endpoints[i].Close)
	}

	var exchanges atomic.Int32
	cts := ctstest.New(t, func(w http.ResponseWriter, _ *http.Request) {
		i := min(int(exchanges.Add(1))-1, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": issued[i]})
	})
	for i, lifetime := range []time.Duration{30 * time.Second, time.Hour} {
		claims := ctstest.Claims()
		claims["exp"] = time.Now().Add(lifetime).Unix()
		claims["services"] = map[string]string{"zerokms": endpoints[i].URL}
		issued[i] = cts.Sign(t, claims)
	}

	key, err := auth.ParseControlAccessKey(ctstest.AccessKey)
	require.NoError(t, err)
	tokens, err := auth.NewTokenSource(t.Context(), workspaceCRN(t), key, auth.WithTransport(cts.Transport()))
	require.NoError(t, err)
	// Both test servers share one CA, so either client's transport trusts both.
	client, err := manage.NewClient(workspaceCRN(t), tokens, manage.WithTransport(endpoints[0].Client().Transport))
	require.NoError(t, err)

	// The first token is inside the refresh margin, so the next operation exchanges again.
	_, err = tokens.Token()
	require.NoError(t, err)
	for range 2 {
		keysets, err := client.ListKeysets(t.Context(), manage.ListKeysetsOptions{})
		require.NoError(t, err)
		assert.Equal(t, []manage.Keyset{{ID: "00000000-0000-4000-8000-000000000001", Name: "tenant"}}, keysets)
	}

	assert.Equal(t, int32(2), exchanges.Load())
	assert.Equal(t, int32(0), requests[0].Load())
	assert.Equal(t, int32(2), requests[1].Load())
}
