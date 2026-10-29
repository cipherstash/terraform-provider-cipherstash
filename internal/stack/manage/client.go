// Package manage administers CipherStash keysets, encryption clients and
// grants through ZeroKMS, and actors and access-key metadata through CTS.
package manage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"golang.org/x/oauth2"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/auth"
	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/cts"
	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/useragent"
	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/zerokms"
)

// Failure categories. The first four are the same values as auth's, so one
// errors.Is check covers authentication and administration failures.
var (
	ErrConfig         = auth.ErrConfig
	ErrAuthentication = auth.ErrAuthentication
	ErrTransport      = auth.ErrTransport
	ErrResponse       = auth.ErrResponse
	ErrForbidden      = errors.New("cipherstash: operation forbidden")
	ErrNotFound       = errors.New("cipherstash: resource not found")
	ErrConflict       = errors.New("cipherstash: resource conflict")
	ErrSecretConsumed = errors.New("cipherstash: creation secret already consumed")
)

// HTTPError reports a non-2xx administration response. It never includes the
// response body, which can contain credentials.
type HTTPError struct {
	Service    string
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("cipherstash: %s returned HTTP %d", e.Service, e.StatusCode)
}

func (e *HTTPError) Unwrap() error {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return ErrAuthentication
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return ErrConflict
	default:
		return ErrResponse
	}
}

const (
	serviceCTS     = "cts"
	serviceZeroKMS = "zerokms"
	// requestTimeout bounds each administration request, not the token
	// acquisition before it. 10 seconds is the default of CipherStash's own
	// (Rust) ZeroKMS HTTP transport.
	requestTimeout = 10 * time.Second
	// zeroKMSPlaceholder is the generated ZeroKMS client's server. The request
	// editor replaces it with the endpoint carried by each token, so a request
	// that bypassed the editor would fail to resolve.
	zeroKMSPlaceholder = "https://zerokms.invalid/"
)

// Client administers one workspace through the generated CTS and ZeroKMS
// clients. It never retries a request. The service authorises each operation.
type Client struct {
	cts     *cts.ClientWithResponses
	zeroKMS *zerokms.ClientWithResponses
}

type ClientOption func(*clientOptions)

type clientOptions struct {
	transport http.RoundTripper
}

// WithTransport sets the transport for administration requests. It does not
// affect the token source's requests. The client still sets a 10-second
// timeout per request and never follows redirects. The default is
// http.DefaultTransport.
func WithTransport(transport http.RoundTripper) ClientOption {
	return func(o *clientOptions) { o.transport = transport }
}

// NewClient makes no network request. tokens must come from
// auth.NewTokenSource, which attaches the verified ZeroKMS endpoint to each
// token. The caller keeps ownership of tokens and its lifetime context.
func NewClient(crn auth.CRN, tokens oauth2.TokenSource, opts ...ClientOption) (*Client, error) {
	if err := crn.Validate(); err != nil {
		return nil, fmt.Errorf("%w: workspace CRN: %w", ErrConfig, err)
	}

	if tokens == nil {
		return nil, fmt.Errorf("%w: token source is required", ErrConfig)
	}

	options := clientOptions{transport: http.DefaultTransport}
	for _, opt := range opts {
		opt(&options)
	}

	if options.transport == nil {
		return nil, fmt.Errorf("%w: transport is required", ErrConfig)
	}

	httpClient := &http.Client{
		Transport:     options.transport,
		Timeout:       requestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	ctsClient, err := cts.NewClientWithResponses(crn.CTSURL(),
		cts.WithHTTPClient(httpClient),
		cts.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
			if _, err := authorize(ctx, tokens, req); err != nil {
				return err
			}

			// CTS administration names the workspace in a header, including on
			// operations whose published schema omits it.
			req.Header.Set("X-Cs-Workspace-Id", crn.WorkspaceID())

			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	zeroKMSClient, err := zerokms.NewClientWithResponses(zeroKMSPlaceholder,
		zerokms.WithHTTPClient(httpClient),
		zerokms.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
			token, err := authorize(ctx, tokens, req)
			if err != nil {
				return err
			}

			endpoint, err := auth.ZeroKMSURL(token)
			if err != nil {
				return err
			}

			routeToZeroKMS(req, endpoint)

			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	return &Client{cts: ctsClient, zeroKMS: zeroKMSClient}, nil
}

// authorize sets one token's credentials on req and returns the token, so the
// ZeroKMS editor routes the request with the endpoint from the same token.
func authorize(ctx context.Context, tokens oauth2.TokenSource, req *http.Request) (*oauth2.Token, error) {
	// Token has no context parameter, so check the caller's context first.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTransport, err)
	}

	token, err := tokens.Token()
	if err != nil {
		return nil, err
	}

	token.SetAuthHeader(req)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", useragent.Value)

	return token, nil
}

// routeToZeroKMS moves a request built against zeroKMSPlaceholder to endpoint,
// keeping the endpoint's path prefix and the request's query.
func routeToZeroKMS(req *http.Request, endpoint *url.URL) {
	target := *endpoint
	target.Path = path.Join("/", endpoint.Path, req.URL.Path)
	target.RawPath = ""
	target.RawQuery = req.URL.RawQuery
	req.URL = &target
	req.Host = target.Host
}

// checkResponse classifies a generated client's result. resp is only read
// when err is nil.
func checkResponse(service string, resp interface{ StatusCode() int }, err error) error {
	if err != nil {
		// Token source and request editor errors already carry a category.
		for _, category := range []error{ErrConfig, ErrAuthentication, ErrTransport, ErrResponse} {
			if errors.Is(err, category) {
				return err
			}
		}

		_, isSyntaxError := errors.AsType[*json.SyntaxError](err)
		_, isTypeError := errors.AsType[*json.UnmarshalTypeError](err)
		if isSyntaxError || isTypeError {
			// Omit the cause, which can quote the response body.
			return fmt.Errorf("%w: malformed %s response", ErrResponse, service)
		}

		return fmt.Errorf("%w: %s: %w", ErrTransport, service, err)
	}

	if status := resp.StatusCode(); status < http.StatusOK || status >= http.StatusMultipleChoices {
		return &HTTPError{Service: service, StatusCode: status}
	}

	return nil
}
