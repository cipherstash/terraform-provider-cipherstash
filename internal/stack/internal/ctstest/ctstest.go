// Package ctstest serves a fake CipherStash Token Service over TLS that signs
// tokens with a test key, for auth and manage tests.
package ctstest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/cts"
	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/useragent"
)

const (
	CRN       = "crn:ap-southeast-2.aws:GXT2N5F4X2SKVEJX"
	Workspace = "GXT2N5F4X2SKVEJX"
	AccessKey = "CSAKtest-id.test-secret"
	Host      = "ap-southeast-2.aws.cts.cipherstashmanaged.net"
	Issuer    = "https://" + Host + "/"
	Audience  = "ap-southeast-2.aws.viturhosted.net"

	rsaBits = 2048
)

type CTS struct {
	signing   atomic.Pointer[signingKey]
	rotations int
	transport http.RoundTripper
}

// signingKey is the key the fake signs with and the key set it publishes.
type signingKey struct {
	key  jwk.Key
	jwks []byte
}

// New serves signing keys and validates access-key exchange requests before
// passing them to authorize. Requests without the expected User-Agent fail.
func New(t *testing.T, authorize http.HandlerFunc) *CTS {
	t.Helper()
	c := &CTS{}
	c.Rotate(t)
	server := httptest.NewTLSServer(cts.HandlerWithOptions(fake{cts: c, authorize: authorize}, cts.StdHTTPServerOptions{
		Middlewares: []cts.MiddlewareFunc{requireUserAgent},
	}))
	t.Cleanup(server.Close)
	c.transport = Redirect(t, server, Host)

	return c
}

// Rotate replaces the signing key with a new key under a new key ID and
// publishes only the new key.
func (c *CTS) Rotate(t *testing.T) {
	t.Helper()
	c.rotations++
	key := newKey(t, "cts-test-"+strconv.Itoa(c.rotations))
	public, err := jwk.PublicKeyOf(key)
	require.NoError(t, err)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(public))
	jwks, err := json.Marshal(set)
	require.NoError(t, err)
	c.signing.Store(&signingKey{key: key, jwks: jwks})
}

// fake implements the generated CTS server interface.
type fake struct {
	cts       *CTS
	authorize http.HandlerFunc
}

func (f fake) GetJwksHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(f.cts.signing.Load().jwks)
}

func (f fake) Authorize(w http.ResponseWriter, req *http.Request) {
	var body cts.AuthorizeRequest
	if json.NewDecoder(req.Body).Decode(&body) != nil || body.AccessKey != AccessKey ||
		body.Audience == nil || *body.Audience != Audience {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	f.authorize(w, req)
}

// The administration operations are faked by manage's tests, not here.
func (fake) ListAccessKeys(w http.ResponseWriter, _ *http.Request, _ cts.ListAccessKeysParams) {
	w.WriteHeader(http.StatusNotImplemented)
}

func (fake) ListActors(w http.ResponseWriter, _ *http.Request, _ cts.ListActorsParams) {
	w.WriteHeader(http.StatusNotImplemented)
}

func (fake) CreateActor(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

func (fake) DeleteActor(w http.ResponseWriter, _ *http.Request, _ string, _ cts.DeleteActorParams) {
	w.WriteHeader(http.StatusNotImplemented)
}

func requireUserAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("User-Agent") != useragent.Value {
			http.Error(w, "unsupported User-Agent", http.StatusForbidden)

			return
		}

		next.ServeHTTP(w, req)
	})
}

// Transport routes requests for the real CTS host to the fake, keeping the
// public issuer in signed tokens.
func (c *CTS) Transport() http.RoundTripper { return c.transport }

// Sign returns a compact RS256 JWT signed with the key the fake publishes.
func (c *CTS) Sign(t *testing.T, claims map[string]any) string {
	t.Helper()

	return sign(t, c.signing.Load().key, claims)
}

// SignWithUnpublishedKey signs with a new key under the published key ID, for
// signature failures.
func (c *CTS) SignWithUnpublishedKey(t *testing.T, claims map[string]any) string {
	t.Helper()
	kid, ok := c.signing.Load().key.KeyID()
	require.True(t, ok)

	return sign(t, newKey(t, kid), claims)
}

func newKey(t *testing.T, kid string) jwk.Key {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	require.NoError(t, err)
	key, err := jwk.Import(rsaKey)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.RS256()))
	require.NoError(t, key.Set(jwk.KeyUsageKey, jwk.ForSignature))

	return key
}

// sign signs the claims as given, so tests can send malformed claim values.
func sign(t *testing.T, key jwk.Key, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	token, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), key))
	require.NoError(t, err)

	return string(token)
}

// Claims returns valid claims for a Control token with an hour's lifetime.
func Claims() map[string]any {
	return map[string]any{
		"iss": Issuer, "aud": Audience,
		"exp": time.Now().Add(time.Hour).Unix(), "workspace": Workspace,
		"role_set": []string{"control"}, "services": map[string]string{"zerokms": "https://kms.example/"},
	}
}

// Redirect sends requests for hosts to server, keeping their Host header, and
// leaves other requests on server's TLS transport, which trusts only test
// certificates.
func Redirect(t *testing.T, server *httptest.Server, hosts ...string) http.RoundTripper {
	t.Helper()
	target, err := url.Parse(server.URL)
	require.NoError(t, err)
	base := server.Client().Transport

	return RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if slices.Contains(hosts, req.URL.Host) {
			req = req.Clone(req.Context())
			req.URL.Host = target.Host
		}

		return base.RoundTrip(req)
	})
}

type RoundTripFunc func(*http.Request) (*http.Response, error)

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
