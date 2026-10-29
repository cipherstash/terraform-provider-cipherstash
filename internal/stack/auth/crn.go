package auth

import (
	"context"
	"regexp"
	"strings"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/cts"
	"github.com/invopop/validation"
)

// CRN identifies a CipherStash workspace, without a service suffix.
type CRN struct {
	value string
}

var (
	supportedRegions = []string{
		"ap-southeast-2.aws", "ca-central-1.aws", "eu-central-1.aws", "eu-west-1.aws",
		"us-east-1.aws", "us-east-2.aws", "us-west-1.aws", "us-west-2.aws",
	}
	workspaceIDPattern = regexp.MustCompile(`^[A-Z2-7]{16}$`)
)

// ParseCRN accepts a workspace CRN in a supported CTS region.
func ParseCRN(value string) (CRN, error) {
	prefix, rest, _ := strings.Cut(value, ":")
	region, workspaceID, _ := strings.Cut(rest, ":")
	err := validation.Errors{
		"prefix":       validation.Validate(prefix, validation.Required, validation.In("crn")),
		"region":       validation.Validate(region, validation.Required, validation.In(supportedRegions...)),
		"workspace ID": validation.Validate(workspaceID, validation.Required, validation.Match(workspaceIDPattern)),
	}.Filter()
	if err != nil {
		return CRN{}, err
	}

	return CRN{value: value}, nil
}

func (c CRN) String() string { return c.value }

// Validate rejects the zero value, such as an unset configuration field.
// ParseCRN is the only way to make a nonzero CRN.
func (c CRN) Validate() error { return validation.Validate(c.value, validation.Required) }

func (c *CRN) EnvDecode(_ context.Context, value string) error {
	parsed, err := ParseCRN(value)
	if err != nil {
		return err
	}

	*c = parsed

	return nil
}

// WorkspaceID returns the workspace's 16-character ID.
func (c CRN) WorkspaceID() string { return c.value[strings.LastIndex(c.value, ":")+1:] }

// CTSURL returns the workspace region's CTS base URL, with a trailing slash.
// CTS also issues the workspace's tokens under this URL.
func (c CRN) CTSURL() string {
	// ParseCRN accepts only regions without template braces, so this cannot fail.
	ctsURL, _ := cts.NewServerURL(cts.ServerURLRegionVariable(c.region()))

	return ctsURL
}

// audience is the regional ZeroKMS audience requested from CTS. cts-common's
// ZeroKmsServiceDiscovery uses this FQDN.
func (c CRN) audience() string { return c.region() + ".viturhosted.net" }

// region returns the CRN's region and provider, such as ap-southeast-2.aws.
func (c CRN) region() string {
	region, _, _ := strings.Cut(strings.TrimPrefix(c.value, "crn:"), ":")

	return region
}
