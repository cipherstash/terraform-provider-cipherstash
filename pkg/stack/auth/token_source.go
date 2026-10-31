// Package auth exchanges a CipherStash access key for verified tokens.
//
// NewTokenSource returns an oauth2.TokenSource for one workspace. It exchanges
// the access key with the CipherStash Token Service (CTS) and verifies each
// token's RS256 signature against CTS's published signing keys, its issuer,
// audience, expiry, workspace and role, and the ZeroKMS endpoint it
// advertises. Tokens are cached until one minute before expiry and refreshed
// on demand.
package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/internal/cts"
	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/internal/useragent"
)

// Failure categories. Errors wrap one of these and, where relevant, the
// underlying context or HTTP client error. They never include credentials.
var (
	ErrConfig         = errors.New("cipherstash: invalid configuration")
	ErrAuthentication = errors.New("cipherstash: authentication failed")
	ErrTransport      = errors.New("cipherstash: transport failed")
	ErrResponse       = errors.New("cipherstash: invalid service response")
)

const (
	// requestTimeout bounds each CTS exchange and signing-key request.
	// 10 seconds is the default of CipherStash's own (Rust) ZeroKMS HTTP transport.
	requestTimeout       = 10 * time.Second
	refreshMargin        = time.Minute
	zeroKMSEndpointExtra = "zerokms_endpoint"
)

type Option func(*options)

type options struct {
	transport http.RoundTripper
}

// WithTransport sets the transport for CTS exchanges and signing-key requests.
// The token source still sets its User-Agent, a 10-second timeout per request
// and a no-redirect policy. The default is http.DefaultTransport.
func WithTransport(transport http.RoundTripper) Option {
	return func(o *options) { o.transport = transport }
}

// NewTokenSource validates its configuration without contacting CTS. The key's
// type selects the required role: Control accepts Control or Admin (logging a
// warning for Admin), Admin requires Admin, and Member requires Member.
//
// ctx is the token source's lifetime: every exchange and signing-key request
// uses it. Pass a context that lives as long as the token source's owner, not
// a request context, and cancel it at shutdown. Cancelling it stops a request
// in progress and makes later exchanges fail with ErrTransport, but a cached
// token is still returned until it is within a minute of expiry.
//
// Token has no context parameter, so a call can wait for another caller's
// refresh. The HTTP timeout bounds each request in that refresh.
func NewTokenSource(ctx context.Context, crn CRN, key AccessKey, opts ...Option) (oauth2.TokenSource, error) {
	if err := crn.Validate(); err != nil {
		return nil, fmt.Errorf("%w: workspace CRN: %w", ErrConfig, err)
	}

	if key == nil {
		return nil, fmt.Errorf("%w: access key is required", ErrConfig)
	}

	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("%w: access key: %w", ErrConfig, err)
	}

	options := options{transport: http.DefaultTransport}
	for _, opt := range opts {
		opt(&options)
	}

	if options.transport == nil {
		return nil, fmt.Errorf("%w: transport is required", ErrConfig)
	}

	httpClient := &http.Client{
		Transport:     userAgentTransport{next: options.transport},
		Timeout:       requestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	validator, err := newTokenValidator(crn, key.requiredRole(), httpClient)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	client, err := cts.NewClientWithResponses(crn.CTSURL(), cts.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	return oauth2.ReuseTokenSourceWithExpiry(nil, &tokenSource{
		ctx:       ctx,
		cts:       client,
		accessKey: key.secret(),
		audience:  crn.audience(),
		validator: validator,
	}, refreshMargin), nil
}

// ZeroKMSURL returns the verified ZeroKMS endpoint carried by a token from
// NewTokenSource: an HTTPS URL without credentials, query or fragment, which
// may include a path. CTS can return a ZeroKMS instance in a different region
// from itself, so the endpoint comes from the token, not the CRN. Each call
// returns a new copy, so callers may modify it without affecting the cached
// token that other callers share.
func ZeroKMSURL(token *oauth2.Token) (*url.URL, error) {
	stored, ok := token.Extra(zeroKMSEndpointExtra).(*url.URL)
	if !ok || stored == nil {
		return nil, fmt.Errorf("%w: token has no ZeroKMS endpoint", ErrResponse)
	}

	endpoint := *stored

	return &endpoint, nil
}

//nolint:containedctx // oauth2.TokenSource has no context parameter; exchanges use the lifetime context from NewTokenSource.
type tokenSource struct {
	ctx       context.Context
	cts       *cts.ClientWithResponses
	accessKey string
	audience  string
	validator *tokenValidator
}

// Token exchanges the access key and verifies the signed result. It is
// uncached; NewTokenSource wraps it in oauth2.ReuseTokenSourceWithExpiry.
func (s *tokenSource) Token() (*oauth2.Token, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTransport, err)
	}

	//nolint:gosec // CTS authentication requires sending the access key over TLS.
	resp, err := s.cts.AuthorizeWithResponse(s.ctx, cts.AuthorizeRequest{
		AccessKey: s.accessKey,
		Audience:  &s.audience,
	})
	if err != nil {
		return nil, classify(err, ErrResponse)
	}

	switch resp.StatusCode() {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("%w: CTS authorise returned HTTP %d", ErrAuthentication, resp.StatusCode())
	default:
		return nil, fmt.Errorf("%w: CTS authorise returned HTTP %d", ErrResponse, resp.StatusCode())
	}

	if resp.JSON200 == nil {
		return nil, fmt.Errorf("%w: CTS authorise response has no token", ErrResponse)
	}

	claims, err := s.validator.ValidateToken(s.ctx, resp.JSON200.AccessToken)
	if err != nil {
		return nil, classify(err, ErrAuthentication)
	}

	// Attach the verified endpoint so the reuse cache keeps it paired with this bearer.
	return (&oauth2.Token{
		AccessToken: resp.JSON200.AccessToken,
		TokenType:   "Bearer",
		Expiry:      time.Unix(claims.Expiry, 0),
	}).WithExtra(map[string]any{zeroKMSEndpointExtra: claims.endpoint}), nil
}

// classify reports a malformed signing-key set as a response error. It reports
// HTTP client failures, failures while reading a response body and other
// failed signing-key fetches during token validation, including error
// statuses, as transport errors. It keeps the cause so callers can still match
// context errors.
func classify(err, fallback error) error {
	if errors.Is(err, jwk.ParseError()) {
		return fmt.Errorf("%w: %w", ErrResponse, err)
	}

	_, isNetError := errors.AsType[net.Error](err)
	validationErr, isValidationError := errors.AsType[*core.ValidationError](err)
	if isNetError || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		(isValidationError && validationErr.Code == core.ErrorCodeJWKSFetchFailed) {
		return fmt.Errorf("%w: %w", ErrTransport, err)
	}

	return fmt.Errorf("%w: %w", fallback, err)
}

// CTS rejects signing-key requests using Go's default User-Agent. Auth0 creates
// these requests itself, so a generated-client request editor cannot cover them.
type userAgentTransport struct {
	next http.RoundTripper
}

func (t userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", useragent.Value)

	return t.next.RoundTrip(req)
}
