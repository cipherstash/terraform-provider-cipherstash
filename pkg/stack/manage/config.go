package manage

import "github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/auth"

// Config holds workspace credentials using the Terraform provider's environment names.
// Use a concrete auth.ControlAccessKey, auth.AdminAccessKey or auth.MemberAccessKey
// for K to select the role policy. Decoding validates syntax; token verification
// enforces the role. Application client IDs belong in the consumer's configuration.
type Config[K auth.AccessKey] struct {
	WorkspaceCRN    auth.CRN `env:"CS_WORKSPACE_CRN,required"`
	ClientAccessKey K        `env:"CS_CLIENT_ACCESS_KEY,required"`
}
