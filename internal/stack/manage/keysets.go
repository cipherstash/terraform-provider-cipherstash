package manage

import (
	"context"
	"fmt"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/zerokms"
)

// Keyset describes a ZeroKMS keyset without exposing key material.
type Keyset struct {
	ID          string
	Name        string
	Description string
	IsDisabled  bool
	IsDefault   bool
}

// CreatedKeyset includes the optional client created with the keyset. Export
// or wipe that client's key through the Client field.
type CreatedKeyset struct {
	Keyset

	Client *CreatedClient
}

// CreateKeyset is not retried. After a transport or response error the keyset
// may exist; reconcile with ListKeysets before creating it again.
func (c *Client) CreateKeyset(ctx context.Context, opts CreateKeysetOptions) (*CreatedKeyset, error) {
	resp, err := c.zeroKMS.CreateKeysetWithResponse(ctx, opts)
	if err := checkResponse(serviceZeroKMS, resp, err); err != nil {
		return nil, err
	}

	// The body contains the created client's key.
	defer clear(resp.Body)

	out := resp.JSON200
	if out == nil || out.ID == "" || out.Name == "" || out.Description == nil || out.IsDisabled == nil {
		return nil, fmt.Errorf("%w: incomplete create-keyset response", ErrResponse)
	}

	if (opts.Client != nil && out.Client == nil) || (out.Client != nil && (out.Client.ID == "" || out.Client.ClientKey == "")) {
		return nil, fmt.Errorf("%w: incomplete created keyset client", ErrResponse)
	}

	created := &CreatedKeyset{Keyset: Keyset{
		ID:          out.ID,
		Name:        out.Name,
		Description: *out.Description,
		IsDisabled:  *out.IsDisabled,
		IsDefault:   out.IsDefault != nil && *out.IsDefault,
	}}
	if out.Client != nil {
		// The response has only the client's ID and key; its name comes from the request.
		var name string
		if opts.Client != nil {
			name = opts.Client.Name
		}

		created.Client = &CreatedClient{
			EncryptionClient: EncryptionClient{ID: out.Client.ID, Name: name, KeysetIDs: []string{out.ID}},
			KeysetID:         out.ID,
			secret:           &creationSecret{bytes: []byte(out.Client.ClientKey)},
		}
	}

	return created, nil
}

// ListKeysets returns every keyset; the service does not paginate them.
func (c *Client) ListKeysets(ctx context.Context, opts ListKeysetsOptions) ([]Keyset, error) {
	resp, err := c.zeroKMS.ListKeysetsWithResponse(ctx, opts)
	if err := checkResponse(serviceZeroKMS, resp, err); err != nil {
		return nil, err
	}

	// A missing or null inventory is malformed; an empty array is not.
	if resp.JSON200 == nil || *resp.JSON200 == nil {
		return nil, fmt.Errorf("%w: missing keyset list", ErrResponse)
	}

	keysets := make([]Keyset, 0, len(*resp.JSON200))
	for _, keyset := range *resp.JSON200 {
		if keyset.ID == "" || keyset.Name == "" || keyset.Description == nil || keyset.IsDisabled == nil {
			return nil, fmt.Errorf("%w: incomplete keyset", ErrResponse)
		}

		keysets = append(keysets, Keyset{
			ID:          keyset.ID,
			Name:        keyset.Name,
			Description: *keyset.Description,
			IsDisabled:  *keyset.IsDisabled,
			IsDefault:   keyset.IsDefault != nil && *keyset.IsDefault,
		})
	}

	return keysets, nil
}

// ModifyKeysetOptions leaves nil fields unchanged. A non-nil pointer sends its
// value, including an empty string, for the service to validate.
type ModifyKeysetOptions struct {
	Name        *string
	Description *string
}

// ModifyKeyset changes metadata for the keyset with the given UUID.
func (c *Client) ModifyKeyset(ctx context.Context, id string, opts ModifyKeysetOptions) error {
	resp, err := c.zeroKMS.ModifyKeysetWithResponse(ctx, zerokms.ModifyKeysetRequest{
		KeysetID: id, Name: opts.Name, Description: opts.Description,
	})

	return checkResponse(serviceZeroKMS, resp, err)
}

// EnableKeyset enables the keyset with the given UUID.
func (c *Client) EnableKeyset(ctx context.Context, id string) error {
	resp, err := c.zeroKMS.EnableKeysetWithResponse(ctx, zerokms.EnableKeysetRequest{KeysetID: id})

	return checkResponse(serviceZeroKMS, resp, err)
}

// DisableKeyset disables the keyset with the given UUID. Keysets cannot be deleted.
func (c *Client) DisableKeyset(ctx context.Context, id string) error {
	resp, err := c.zeroKMS.DisableKeysetWithResponse(ctx, zerokms.DisableKeysetRequest{KeysetID: id})

	return checkResponse(serviceZeroKMS, resp, err)
}

// GrantKeyset grants a client access to a keyset. Both IDs are UUIDs.
func (c *Client) GrantKeyset(ctx context.Context, keysetID, clientID string) error {
	resp, err := c.zeroKMS.GrantKeysetWithResponse(ctx, zerokms.GrantKeysetRequest{KeysetID: keysetID, ClientID: clientID})

	return checkResponse(serviceZeroKMS, resp, err)
}

// RevokeKeyset revokes a client's access to a keyset. Both IDs are UUIDs.
func (c *Client) RevokeKeyset(ctx context.Context, keysetID, clientID string) error {
	resp, err := c.zeroKMS.RevokeKeysetWithResponse(ctx, zerokms.RevokeKeysetRequest{KeysetID: keysetID, ClientID: clientID})

	return checkResponse(serviceZeroKMS, resp, err)
}
