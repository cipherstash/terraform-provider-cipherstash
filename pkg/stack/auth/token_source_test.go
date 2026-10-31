package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/auth"
	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/internal/ctstest"
)

// issue returns an authorise handler that counts exchanges and returns the current token.
func issue(current *atomic.Value, exchanges *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		exchanges.Add(1)
		// The unsigned expiry deliberately disagrees with the signed claim.
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": current.Load(), "expiry": 1})
	}
}

func newTokenSource(ctx context.Context, t *testing.T, key auth.AccessKey, transport http.RoundTripper) oauth2.TokenSource {
	t.Helper()
	crn, err := auth.ParseCRN(testCRN)
	require.NoError(t, err)
	tokens, err := auth.NewTokenSource(ctx, crn, key, auth.WithTransport(transport))
	require.NoError(t, err)

	return tokens
}

func zeroKMSURL(t *testing.T, token *oauth2.Token) string {
	t.Helper()
	endpoint, err := auth.ZeroKMSURL(token)
	require.NoError(t, err)

	return endpoint.String()
}

func controlKey(t *testing.T) auth.ControlAccessKey {
	t.Helper()
	key, err := auth.ParseControlAccessKey(ctstest.AccessKey)
	require.NoError(t, err)

	return key
}

func TestTokenSourceRolePolicies(t *testing.T) {
	adminKey, err := auth.ParseAdminAccessKey(ctstest.AccessKey)
	require.NoError(t, err)
	memberKey, err := auth.ParseMemberAccessKey(ctstest.AccessKey)
	require.NoError(t, err)
	for _, policy := range []struct {
		name   string
		key    auth.AccessKey
		allows map[string]bool
	}{
		{"control", controlKey(t), map[string]bool{"control": true, "admin": true}},
		{"admin", adminKey, map[string]bool{"admin": true}},
		{"member", memberKey, map[string]bool{"member": true}},
	} {
		for _, role := range []string{"control", "admin", "member", "unknown"} {
			t.Run(policy.name+" key with "+role+" role", func(t *testing.T) {
				var current atomic.Value
				var exchanges atomic.Int32
				cts := ctstest.New(t, issue(&current, &exchanges))
				endpoint := "https://" + role + ".example/keys/"
				claims := ctstest.Claims()
				claims["role_set"] = []string{role}
				claims["services"] = map[string]string{"zerokms": endpoint}
				signed := cts.Sign(t, claims)
				current.Store(signed)

				token, err := newTokenSource(t.Context(), t, policy.key, cts.Transport()).Token()
				if !policy.allows[role] {
					require.ErrorIs(t, err, auth.ErrAuthentication)
					assert.Nil(t, token)

					return
				}

				require.NoError(t, err)
				assert.Equal(t, signed, token.AccessToken)
				assert.Equal(t, endpoint, zeroKMSURL(t, token))
			})
		}
	}
}

func TestTokenSourceVerifiesSignedClaims(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changes map[string]any
		valid   bool
	}{
		{"valid", nil, true},
		{"case insensitive scalar", map[string]any{"role_set": "CoNtRoL"}, true},
		{"endpoint path", map[string]any{"services": map[string]string{"zerokms": "https://kms.example/base"}}, true},
		{"wrong issuer", map[string]any{"iss": "https://other.example/"}, false},
		{"wrong audience", map[string]any{"aud": "other.example"}, false},
		{"wrong workspace", map[string]any{"workspace": "AAAAAAAAAAAAAAAA"}, false},
		{"missing expiry", map[string]any{"exp": nil}, false},
		{"expired", map[string]any{"exp": time.Now().Add(-2 * time.Minute).Unix()}, false},
		{"clock skew", map[string]any{"exp": time.Now().Add(-10 * time.Second).Unix()}, true},
		{"missing roles", map[string]any{"role_set": nil}, false},
		{"null roles", map[string]any{"role_set": json.RawMessage("null")}, false},
		{"empty roles", map[string]any{"role_set": []string{}}, false},
		{"missing endpoint", map[string]any{"services": map[string]string{}}, false},
		{"http endpoint", map[string]any{"services": map[string]string{"zerokms": "http://kms.example/"}}, false},
		{"endpoint userinfo", map[string]any{"services": map[string]string{"zerokms": "https://secret@kms.example/"}}, false},
		{"endpoint query", map[string]any{"services": map[string]string{"zerokms": "https://kms.example/?token=secret"}}, false},
		{"endpoint fragment", map[string]any{"services": map[string]string{"zerokms": "https://kms.example/#secret"}}, false},
		{"wrong signature", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var current atomic.Value
			var exchanges atomic.Int32
			cts := ctstest.New(t, issue(&current, &exchanges))
			claims := ctstest.Claims()
			for key, value := range tc.changes {
				if value == nil {
					delete(claims, key)
				} else {
					claims[key] = value
				}
			}

			if tc.name == "wrong signature" {
				current.Store(cts.SignWithUnpublishedKey(t, claims))
			} else {
				current.Store(cts.Sign(t, claims))
			}

			token, err := newTokenSource(t.Context(), t, controlKey(t), cts.Transport()).Token()
			if tc.valid {
				require.NoError(t, err)
				assert.NotEmpty(t, token.AccessToken)
			} else {
				require.ErrorIs(t, err, auth.ErrAuthentication)
				assert.Nil(t, token)
				assert.NotContains(t, err.Error(), "secret")
			}
		})
	}
}

func TestTokenSourceClassifiesExchangeFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		handle http.HandlerFunc
		target error
	}{
		{"rejected credential", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"CSAKtest-id.test-secret"}`, http.StatusUnauthorized)
		}, auth.ErrAuthentication},
		{"forbidden credential", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}, auth.ErrAuthentication},
		{"service failure", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, auth.ErrResponse},
		{"malformed body", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("{"))
		}, auth.ErrResponse},
		{"dropped connection", func(w http.ResponseWriter, _ *http.Request) {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}, auth.ErrTransport},
		{"truncated body", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte(`{"accessToken":`))
		}, auth.ErrTransport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cts := ctstest.New(t, tc.handle)
			_, err := newTokenSource(t.Context(), t, controlKey(t), cts.Transport()).Token()
			require.ErrorIs(t, err, tc.target)
			assert.NotContains(t, err.Error(), "secret")
		})
	}
}

func TestTokenSourceReportsConnectionResetMidBodyAsTransportFailure(t *testing.T) {
	cts := ctstest.New(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"accessToken":"unused"}`))
	})
	base := cts.Transport()
	transport := ctstest.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := base.RoundTrip(req)
		if err == nil && req.URL.Path == "/api/authorise" {
			_ = resp.Body.Close()
			reset := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
			resp.Body = io.NopCloser(io.MultiReader(strings.NewReader(`{"accessToken":`), iotest.ErrReader(reset)))
		}

		return resp, err
	})

	_, err := newTokenSource(t.Context(), t, controlKey(t), transport).Token()
	require.ErrorIs(t, err, auth.ErrTransport)
}

func TestTokenSourceClassifiesSigningKeyFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		target error
	}{
		{"error status", http.StatusServiceUnavailable, `{"message":"unavailable"}`, auth.ErrTransport},
		{"malformed key set", http.StatusOK, `{"keys":"none"}`, auth.ErrResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var current atomic.Value
			var exchanges atomic.Int32
			cts := ctstest.New(t, issue(&current, &exchanges))
			current.Store(cts.Sign(t, ctstest.Claims()))
			base := cts.Transport()
			var signingKeyRequests atomic.Int32
			transport := ctstest.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/.well-known/jwks.json" && signingKeyRequests.Add(1) == 1 {
					return &http.Response{
						StatusCode: tc.status, Header: http.Header{"Content-Type": []string{"application/json"}},
						Body: io.NopCloser(strings.NewReader(tc.body)), Request: req,
					}, nil
				}

				return base.RoundTrip(req)
			})
			tokens := newTokenSource(t.Context(), t, controlKey(t), transport)

			_, err := tokens.Token()
			require.ErrorIs(t, err, tc.target)
			_, err = tokens.Token()
			require.NoError(t, err, "the next exchange must fetch the signing keys again")
			assert.Equal(t, int32(2), signingKeyRequests.Load())
		})
	}
}

func TestTokenSourceUsesRotatedSigningKeys(t *testing.T) {
	var current atomic.Value
	var exchanges atomic.Int32
	cts := ctstest.New(t, issue(&current, &exchanges))
	// Expiring within the refresh margin, so every Token call exchanges again.
	claims := ctstest.Claims()
	claims["exp"] = time.Now().Add(30 * time.Second).Unix()
	beforeRotation := cts.Sign(t, claims)
	current.Store(beforeRotation)
	tokens := newTokenSource(t.Context(), t, controlKey(t), cts.Transport())
	_, err := tokens.Token()
	require.NoError(t, err)

	cts.Rotate(t)
	current.Store(cts.Sign(t, claims))
	_, err = tokens.Token()
	require.NoError(t, err, "a token signed with the rotated key must verify at once")

	current.Store(beforeRotation)
	_, err = tokens.Token()
	require.ErrorIs(t, err, auth.ErrAuthentication, "a token signed with the withdrawn key must fail")
	assert.Equal(t, int32(3), exchanges.Load())
}

func TestTokenSourceRejectsRedirects(t *testing.T) {
	for _, redirectPath := range []string{"/api/authorise", "/.well-known/jwks.json"} {
		t.Run(redirectPath, func(t *testing.T) {
			var leaked atomic.Bool
			target := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				leaked.Store(true)
			}))
			t.Cleanup(target.Close)
			var current atomic.Value
			var exchanges atomic.Int32
			cts := ctstest.New(t, issue(&current, &exchanges))
			current.Store(cts.Sign(t, ctstest.Claims()))
			base := cts.Transport()
			transport := ctstest.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == redirectPath {
					return &http.Response{
						StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{target.URL}},
						Body: http.NoBody, Request: req,
					}, nil
				}

				if req.URL.Host != ctstest.Host {
					return target.Client().Transport.RoundTrip(req)
				}

				return base.RoundTrip(req)
			})

			_, err := newTokenSource(t.Context(), t, controlKey(t), transport).Token()
			require.Error(t, err)
			assert.False(t, leaked.Load(), "redirect target must never receive an authentication request")
		})
	}
}

func TestTokenSourceKeepsRefreshedBearerAndEndpointTogether(t *testing.T) {
	var current atomic.Value
	var exchanges atomic.Int32
	cts := ctstest.New(t, issue(&current, &exchanges))
	claims := ctstest.Claims()
	// Valid, but inside the one-minute refresh margin.
	claims["exp"] = time.Now().Add(30 * time.Second).Unix()
	claims["services"] = map[string]string{"zerokms": "https://old.example/"}
	initial := cts.Sign(t, claims)
	current.Store(initial)
	tokens := newTokenSource(t.Context(), t, controlKey(t), cts.Transport())
	token, err := tokens.Token()
	require.NoError(t, err)
	assert.Equal(t, initial, token.AccessToken)

	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["services"] = map[string]string{"zerokms": "https://new.example/"}
	refreshed := cts.Sign(t, claims)
	current.Store(refreshed)
	token, err = tokens.Token()
	require.NoError(t, err)
	assert.Equal(t, refreshed, token.AccessToken)
	assert.Equal(t, "https://new.example/", zeroKMSURL(t, token))

	// The cached token is shared, so a caller's changes to its URL must not leak.
	endpoint, err := auth.ZeroKMSURL(token)
	require.NoError(t, err)
	endpoint.Host = "mutated.example"
	assert.Equal(t, "https://new.example/", zeroKMSURL(t, token))

	// A healthy cached token is reused without another exchange.
	current.Store("invalid token")
	token, err = tokens.Token()
	require.NoError(t, err)
	assert.Equal(t, refreshed, token.AccessToken)
	assert.Equal(t, int32(2), exchanges.Load())
}

func TestTokenSourceCancellation(t *testing.T) {
	t.Run("cancelled lifetime", func(t *testing.T) {
		var current atomic.Value
		var exchanges atomic.Int32
		cts := ctstest.New(t, issue(&current, &exchanges))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		token, err := newTokenSource(ctx, t, controlKey(t), cts.Transport()).Token()
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, auth.ErrTransport)
		assert.Nil(t, token)
		assert.Zero(t, exchanges.Load())
	})

	t.Run("cancelling the lifetime stops an exchange in progress", func(t *testing.T) {
		started := make(chan struct{})
		cts := ctstest.New(t, func(_ http.ResponseWriter, req *http.Request) {
			close(started)
			<-req.Context().Done()
		})
		ctx, cancel := context.WithCancel(t.Context())
		tokens := newTokenSource(ctx, t, controlKey(t), cts.Transport())
		go func() {
			<-started
			cancel()
		}()
		begin := time.Now()
		_, err := tokens.Token()
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, auth.ErrTransport)
		assert.Less(t, time.Since(begin), 10*time.Second, "cancellation must not wait for the HTTP timeout")
	})
}

func TestFormattingRedactsAccessKeys(t *testing.T) {
	key := controlKey(t)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, value := range []any{key, &key} {
			assert.NotContains(t, fmt.Sprintf(verb, value), "secret", verb)
		}
	}
}
