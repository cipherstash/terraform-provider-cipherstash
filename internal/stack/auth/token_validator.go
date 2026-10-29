package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/invopop/validation"
)

type tokenValidator struct {
	jwtValidator *validator.Validator
}

func newTokenValidator(crn CRN, requiredRole string, httpClient *http.Client) (*tokenValidator, error) {
	issuer, err := url.Parse(crn.CTSURL())
	if err != nil {
		return nil, err
	}

	// The uncaching provider fetches the signing keys during each token
	// exchange, under the token source's lifetime context, so a rotated key is
	// used at once and no background refresh outlives the token source.
	provider, err := jwks.NewProvider(
		jwks.WithIssuerURL(issuer),
		jwks.WithCustomJWKSURI(issuer.JoinPath(".well-known/jwks.json")),
		jwks.WithCustomClient(httpClient),
	)
	if err != nil {
		return nil, err
	}

	jwtValidator, err := validator.New(
		validator.WithKeyFunc(provider.KeyFunc),
		validator.WithAlgorithm(validator.RS256),
		validator.WithIssuer(issuer.String()),
		validator.WithAudience(crn.audience()),
		validator.WithCustomClaims(func() *claims {
			return &claims{expectedWorkspace: crn.WorkspaceID(), requiredRole: requiredRole}
		}),
		validator.WithAllowedClockSkew(time.Minute),
	)
	if err != nil {
		return nil, err
	}

	return &tokenValidator{jwtValidator: jwtValidator}, nil
}

func (v *tokenValidator) ValidateToken(ctx context.Context, token string) (*claims, error) {
	valid, err := v.jwtValidator.ValidateToken(ctx, token)
	if err != nil {
		return nil, err
	}

	validatedClaims, ok := valid.(*validator.ValidatedClaims)
	if !ok {
		return nil, errors.New("unexpected token type")
	}

	customClaims, ok := validatedClaims.CustomClaims.(*claims)
	if !ok {
		return nil, errors.New("unexpected CTS claims type")
	}

	return customClaims, nil
}

type claims struct {
	Workspace string   `json:"workspace"`
	Expiry    int64    `json:"exp"`
	RoleSet   roles    `json:"role_set"` //nolint:tagliatelle // CTS uses snake_case for this claim.
	Services  services `json:"services"`

	expectedWorkspace string
	requiredRole      string
	endpoint          *url.URL
}

func (c *claims) Validate(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, c,
		validation.Field(&c.Workspace, validation.Required, validation.In(c.expectedWorkspace)),
		// Auth0 validates exp when present, but does not require it.
		validation.Field(&c.Expiry, validation.Required),
		validation.Field(&c.RoleSet, validation.Required, validation.WithContext(c.validateRoles)),
		validation.Field(&c.Services, validation.By(c.parseZeroKMSEndpoint)),
	)
}

func (c *claims) validateRoles(ctx context.Context, _ any) error {
	if c.requiredRole == "control" && c.RoleSet.has("admin") {
		slog.WarnContext(ctx,
			"CipherStash Control credential is not Control-only; "+
				"prefer a dedicated Control access key",
			"roles", c.RoleSet,
		)

		return nil
	}

	if !c.RoleSet.has(c.requiredRole) {
		return fmt.Errorf("CipherStash access key must have the %s role", c.requiredRole)
	}

	return nil
}

// parseZeroKMSEndpoint keeps the parsed endpoint for the token.
func (c *claims) parseZeroKMSEndpoint(any) error {
	endpoint, err := url.Parse(c.Services.ZeroKMS)
	if err != nil {
		return errors.New("invalid ZeroKMS endpoint")
	}

	if endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("ZeroKMS endpoint must be an HTTPS URL without credentials, query, or fragment")
	}

	c.endpoint = endpoint

	return nil
}

// roles matches cts-common's RoleSet, which accepts a string or string array.
type roles []string

func (r *roles) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, (*[]string)(r)); err == nil {
		return nil
	}

	var role string
	if err := json.Unmarshal(data, &role); err != nil {
		return err
	}

	*r = roles{role}

	return nil
}

func (r roles) has(role string) bool {
	return slices.ContainsFunc(r, func(candidate string) bool { return strings.EqualFold(candidate, role) })
}

// services contains the service discovery URLs advertised by CTS.
type services struct {
	ZeroKMS string `json:"zerokms"`
}
