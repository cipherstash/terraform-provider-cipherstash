package auth_test

import (
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/auth"
	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/ctstest"
	"github.com/invopop/validation"
	"github.com/sethvargo/go-envconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"pgregory.net/rapid"
)

const testCRN = ctstest.CRN

// supportedRegions is the test's own copy of the regions ParseCRN must accept.
var supportedRegions = []string{
	"ap-southeast-2.aws", "ca-central-1.aws", "eu-central-1.aws", "eu-west-1.aws",
	"us-east-1.aws", "us-east-2.aws", "us-west-1.aws", "us-west-2.aws",
}

type crnParts struct{ region, workspaceID string }

func (p crnParts) String() string { return "crn:" + p.region + ":" + p.workspaceID }

func validCRNParts() *rapid.Generator[crnParts] {
	return rapid.Custom(func(t *rapid.T) crnParts {
		return crnParts{
			region:      rapid.SampledFrom(supportedRegions).Draw(t, "region"),
			workspaceID: rapid.StringMatching(`[A-Z2-7]{16}`).Draw(t, "workspace_id"),
		}
	})
}

func TestParseCRN(t *testing.T) {
	t.Run("valid", rapid.MakeCheck(func(t *rapid.T) {
		parts := validCRNParts().Draw(t, "crn")
		crn, err := auth.ParseCRN(parts.String())
		require.NoError(t, err)
		assert.Equal(t, parts.String(), crn.String())
		assert.Equal(t, parts.workspaceID, crn.WorkspaceID())
		assert.Equal(t, "https://"+parts.region+".cts.cipherstashmanaged.net/", crn.CTSURL())
		require.NoError(t, validation.Validate(crn))

		var decoded auth.CRN
		require.NoError(t, decoded.EnvDecode(t.Context(), parts.String()))
		assert.Equal(t, crn, decoded)
	}))

	t.Run("invalid", rapid.MakeCheck(func(t *rapid.T) {
		parts := validCRNParts().Draw(t, "crn")
		rest := parts.region + ":" + parts.workspaceID
		var value string
		switch rapid.SampledFrom([]string{"prefix", "region", "id length", "id character", "suffix", "whitespace"}).Draw(t, "mutation") {
		case "prefix":
			// Replaces "crn:". No supported region starts with "crn:" or ":", so the value never starts with "crn:".
			prefix := rapid.OneOf(
				rapid.Just(""), rapid.Just("CRN:"), rapid.Just("crn"),
				rapid.Map(rapid.StringMatching(`[^:]*`), func(s string) string { return s + ":" }),
			).Filter(func(p string) bool { return p != "crn:" }).Draw(t, "prefix")
			value = prefix + rest
		case "region":
			region := rapid.OneOf(
				rapid.Map(rapid.SampledFrom(supportedRegions), strings.ToUpper),
				rapid.Map(rapid.SampledFrom(supportedRegions), func(r string) string { return strings.TrimSuffix(r, ".aws") }),
				rapid.Map(rapid.SampledFrom(supportedRegions), func(r string) string { return strings.TrimSuffix(r, ".aws") + ".gcp" }),
				rapid.Custom(func(t *rapid.T) string { // a neighbouring region such as eu-west-2.aws
					r := rapid.SampledFrom(supportedRegions).Draw(t, "base_region")
					i := strings.IndexAny(r, "0123456789")

					return r[:i] + string(rapid.RuneFrom([]rune("0123456789")).Draw(t, "digit")) + r[i+1:]
				}),
				rapid.StringMatching(`[^:]*`),
			).Filter(func(r string) bool { return !slices.Contains(supportedRegions, r) }).Draw(t, "region")
			value = "crn:" + region + ":" + parts.workspaceID
		case "id length":
			length := rapid.IntRange(0, 32).Filter(func(n int) bool { return n != 16 }).Draw(t, "id_length")
			value = "crn:" + parts.region + ":" + rapid.StringMatching(fmt.Sprintf(`[A-Z2-7]{%d}`, length)).Draw(t, "workspace_id")
		case "id character":
			i := rapid.IntRange(0, 15).Draw(t, "index")
			char := rapid.OneOf(rapid.RuneFrom([]rune("az0189:=% é")), rapid.Rune()).
				Filter(func(r rune) bool { return (r < 'A' || r > 'Z') && (r < '2' || r > '7') }).Draw(t, "char")
			value = "crn:" + parts.region + ":" + parts.workspaceID[:i] + string(char) + parts.workspaceID[i+1:]
		case "suffix":
			value = parts.String() + ":" + rapid.OneOf(rapid.Just("zerokms"), rapid.String()).Draw(t, "suffix")
		case "whitespace":
			space := rapid.StringMatching(`[\s\x{a0}\x{2003}\x{3000}]+`).Draw(t, "whitespace")
			if rapid.Bool().Draw(t, "leading") {
				value = space + parts.String()
			} else {
				value = parts.String() + space
			}
		}

		crn, err := auth.ParseCRN(value)
		require.Error(t, err, value)
		assert.Zero(t, crn)
	}))
}

func TestAccessKeyParsingAndEnvconfig(t *testing.T) {
	for _, value := range []string{"", "csakid.secret", "CSAK", "CSAKid", "CSAK.secret", "CSAKid."} {
		t.Run(value, func(t *testing.T) {
			_, err := auth.ParseControlAccessKey(value)
			require.Error(t, err)
			_, err = auth.ParseAdminAccessKey(value)
			require.Error(t, err)
			_, err = auth.ParseMemberAccessKey(value)
			require.Error(t, err)
		})
	}

	var cfg struct {
		CRN     auth.CRN              `env:"CS_WORKSPACE_CRN,required"`
		Control auth.ControlAccessKey `env:"CS_CONTROL_ACCESS_KEY,required"`
		Admin   auth.AdminAccessKey   `env:"CS_ADMIN_ACCESS_KEY,required"`
		Member  auth.MemberAccessKey  `env:"CS_MEMBER_ACCESS_KEY,required"`
	}
	values := map[string]string{
		"CS_WORKSPACE_CRN": testCRN, "CS_CONTROL_ACCESS_KEY": ctstest.AccessKey,
		"CS_ADMIN_ACCESS_KEY": ctstest.AccessKey, "CS_MEMBER_ACCESS_KEY": ctstest.AccessKey,
	}
	err := envconfig.ProcessWith(t.Context(), &envconfig.Config{Target: &cfg, Lookuper: envconfig.MapLookuper(values)})
	require.NoError(t, err)
	crn, err := auth.ParseCRN(testCRN)
	require.NoError(t, err)
	controlKey, err := auth.ParseControlAccessKey(ctstest.AccessKey)
	require.NoError(t, err)
	adminKey, err := auth.ParseAdminAccessKey(ctstest.AccessKey)
	require.NoError(t, err)
	memberKey, err := auth.ParseMemberAccessKey(ctstest.AccessKey)
	require.NoError(t, err)
	assert.Equal(t, crn, cfg.CRN)
	assert.Equal(t, controlKey, cfg.Control)
	assert.Equal(t, adminKey, cfg.Admin)
	assert.Equal(t, memberKey, cfg.Member)

	for field := range values {
		t.Run(field, func(t *testing.T) {
			previous := cfg
			value := values[field]
			values[field] = "invalid"
			err := envconfig.ProcessWith(t.Context(), &envconfig.Config{
				Target: &cfg, Lookuper: envconfig.MapLookuper(values), DefaultOverwrite: true,
			})
			require.Error(t, err)
			assert.Equal(t, previous, cfg, "failed decoding must not replace a parsed value")
			values[field] = value
		})
	}

	// Distinct private fields prevent explicit conversion between credential types.
	types := []reflect.Type{reflect.TypeFor[auth.ControlAccessKey](), reflect.TypeFor[auth.AdminAccessKey](), reflect.TypeFor[auth.MemberAccessKey]()}
	for _, from := range types {
		for _, to := range types {
			assert.Equal(t, from == to, from.ConvertibleTo(to))
		}
	}

	// Configuration structs are commonly logged; the keys must not appear.
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		assert.NotContains(t, fmt.Sprintf(verb, cfg), "secret", verb)
	}
}

func TestNewTokenSourceRejectsInvalidConfigurationWithoutNetwork(t *testing.T) {
	crn, err := auth.ParseCRN(testCRN)
	require.NoError(t, err)
	key, err := auth.ParseControlAccessKey(ctstest.AccessKey)
	require.NoError(t, err)
	noNetwork := auth.WithTransport(ctstest.RoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("construction must not contact CTS")

		return nil, http.ErrNotSupported
	}))
	for name, construct := range map[string]func() (oauth2.TokenSource, error){
		"zero CRN": func() (oauth2.TokenSource, error) {
			return auth.NewTokenSource(t.Context(), auth.CRN{}, key, noNetwork)
		},
		"nil key": func() (oauth2.TokenSource, error) { return auth.NewTokenSource(t.Context(), crn, nil, noNetwork) },
		"zero Control key": func() (oauth2.TokenSource, error) {
			return auth.NewTokenSource(t.Context(), crn, auth.ControlAccessKey{}, noNetwork)
		},
		"zero Admin key": func() (oauth2.TokenSource, error) {
			return auth.NewTokenSource(t.Context(), crn, auth.AdminAccessKey{}, noNetwork)
		},
		"zero Member key": func() (oauth2.TokenSource, error) {
			return auth.NewTokenSource(t.Context(), crn, auth.MemberAccessKey{}, noNetwork)
		},
		"nil transport": func() (oauth2.TokenSource, error) {
			return auth.NewTokenSource(t.Context(), crn, key, auth.WithTransport(nil))
		},
	} {
		t.Run(name, func(t *testing.T) {
			tokens, err := construct()
			require.ErrorIs(t, err, auth.ErrConfig)
			assert.Nil(t, tokens)
		})
	}

	tokens, err := auth.NewTokenSource(t.Context(), crn, key, noNetwork)
	require.NoError(t, err)
	assert.NotNil(t, tokens)
}
