package manage

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/zerokms"
	"github.com/hashicorp/go-uuid"
)

// EncryptionClient is a ZeroKMS client identity, distinct from the
// administrative Client. KeysetIDs lists every keyset it is granted.
type EncryptionClient struct {
	ID          string
	Name        string
	Description string
	KeysetIDs   []string
}

// CreatedClient holds the client's metadata and its once-returned key.
// Copies share one extraction right: export the key once, or wipe it.
type CreatedClient struct {
	EncryptionClient

	KeysetID string
	secret   *creationSecret
}

// ExportClientKey returns the base64-encoded client key for persistence. The
// caller owns the bytes and should clear them after use. Later calls on this
// result or any copy return ErrSecretConsumed.
func (c *CreatedClient) ExportClientKey() ([]byte, error) {
	if c == nil {
		return nil, ErrSecretConsumed
	}

	return c.secret.take()
}

// Wipe clears a client key that will not be exported. It is nil-safe and idempotent.
func (c *CreatedClient) Wipe() {
	if c != nil {
		c.secret.wipe()
	}
}

// Format redacts the result for every fmt verb, including in logs.
func (CreatedClient) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "manage.CreatedClient(***)")
}

// CreateClient is not retried. After a transport or response error the client
// may exist; reconcile with ListClients before creating it again.
func (c *Client) CreateClient(ctx context.Context, opts CreateClientOptions) (*CreatedClient, error) {
	resp, err := c.zeroKMS.CreateClientWithResponse(ctx, opts)
	if err := checkResponse(serviceZeroKMS, resp, err); err != nil {
		return nil, err
	}

	// The body contains the client key.
	defer clear(resp.Body)

	out := resp.JSON200
	if out == nil || out.ID == "" || out.Name == "" || out.Description == nil || out.DatasetID == "" || out.ClientKey == "" {
		return nil, fmt.Errorf("%w: incomplete create-client response", ErrResponse)
	}

	return &CreatedClient{
		EncryptionClient: EncryptionClient{
			ID:          out.ID,
			Name:        out.Name,
			Description: *out.Description,
			KeysetIDs:   []string{out.DatasetID},
		},
		KeysetID: out.DatasetID,
		secret:   &creationSecret{bytes: []byte(out.ClientKey)},
	}, nil
}

// ListClientsOptions filters by a keyset UUID; empty lists every client.
type ListClientsOptions struct {
	KeysetID string
}

// ListClients returns every matching client; the service does not paginate them.
func (c *Client) ListClients(ctx context.Context, opts ListClientsOptions) ([]EncryptionClient, error) {
	var input zerokms.ListClientRequest
	if opts.KeysetID != "" {
		input.KeysetID = &zerokms.IdentifiedBy{}
		if err := input.KeysetID.FromIdentifiedBy0(zerokms.IdentifiedBy0{UUID: opts.KeysetID}); err != nil {
			return nil, fmt.Errorf("%w: keyset filter: %w", ErrConfig, err)
		}
	}

	resp, err := c.zeroKMS.ListClientsWithResponse(ctx, input)
	if err := checkResponse(serviceZeroKMS, resp, err); err != nil {
		return nil, err
	}

	// A missing or null inventory is malformed; an empty array is not.
	if resp.JSON200 == nil || *resp.JSON200 == nil {
		return nil, fmt.Errorf("%w: missing client list", ErrResponse)
	}

	clients := make([]EncryptionClient, 0, len(*resp.JSON200))
	for _, item := range *resp.JSON200 {
		if _, err := uuid.ParseUUID(item.ID); err != nil {
			return nil, fmt.Errorf("%w: invalid client UUID", ErrResponse)
		}

		if item.Name == "" || item.Description == nil {
			return nil, fmt.Errorf("%w: incomplete client metadata", ErrResponse)
		}

		// The service returns one keyset ID or an array of them.
		ids, err := item.KeysetID.AsClientKeysetID1()
		if err != nil {
			id, err := item.KeysetID.AsClientKeysetID0()
			if err != nil {
				return nil, fmt.Errorf("%w: invalid client keyset associations", ErrResponse)
			}

			ids = []string{id}
		}

		if ids == nil || slices.Contains(ids, "") {
			return nil, fmt.Errorf("%w: missing client keyset association", ErrResponse)
		}
		for _, id := range ids {
			if _, err := uuid.ParseUUID(id); err != nil {
				return nil, fmt.Errorf("%w: invalid client keyset UUID", ErrResponse)
			}
		}

		clients = append(clients, EncryptionClient{ID: item.ID, Name: item.Name, Description: *item.Description, KeysetIDs: ids})
	}

	if err := checkInventoryDuplicates(resp.Body); err != nil {
		return nil, err
	}

	return clients, nil
}

// DeleteClient deletes the client with the given UUID.
func (c *Client) DeleteClient(ctx context.Context, id string) error {
	resp, err := c.zeroKMS.DeleteClientWithResponse(ctx, zerokms.DeleteClientRequest{ClientID: id})

	return checkResponse(serviceZeroKMS, resp, err)
}
