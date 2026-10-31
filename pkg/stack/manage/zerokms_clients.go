package manage

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/google/uuid"

	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/internal/zerokms"
)

// ZeroKMSClient is a ZeroKMS client identity, distinct from the
// administrative Client. KeysetIDs lists every keyset it is granted.
type ZeroKMSClient struct {
	ID          string
	Name        string
	Description string
	KeysetIDs   []string
}

// CreatedZeroKMSClient holds the client's metadata and its once-returned key.
// Copies share one extraction right: export the key once, or wipe it.
type CreatedZeroKMSClient struct {
	ZeroKMSClient

	KeysetID string
	secret   *creationSecret
}

// ExportClientKey returns the base64-encoded client key for persistence. The
// caller owns the bytes and should clear them after use. Later calls on this
// result or any copy return ErrSecretConsumed.
func (c *CreatedZeroKMSClient) ExportClientKey() ([]byte, error) {
	if c == nil {
		return nil, ErrSecretConsumed
	}

	return c.secret.take()
}

// Wipe clears a client key that will not be exported. It is nil-safe and idempotent.
func (c *CreatedZeroKMSClient) Wipe() {
	if c != nil {
		c.secret.wipe()
	}
}

// Format redacts the result for every fmt verb, including in logs.
func (CreatedZeroKMSClient) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "manage.CreatedZeroKMSClient(***)")
}

// CreateZeroKMSClient is not retried. After a transport or response error the client
// may exist; reconcile with ListZeroKMSClients before creating it again.
func (c *Client) CreateZeroKMSClient(ctx context.Context, opts CreateZeroKMSClientOptions) (*CreatedZeroKMSClient, error) {
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

	return &CreatedZeroKMSClient{
		ID:          out.ID,
		Name:        out.Name,
		Description: *out.Description,
		KeysetIDs:   []string{out.DatasetID},
		KeysetID:    out.DatasetID,
		secret:      &creationSecret{bytes: []byte(out.ClientKey)},
	}, nil
}

// ListZeroKMSClientsOptions filters by a keyset UUID; empty lists every client.
type ListZeroKMSClientsOptions struct {
	KeysetID string
}

// ListZeroKMSClients returns every matching client; the service does not paginate them.
func (c *Client) ListZeroKMSClients(ctx context.Context, opts ListZeroKMSClientsOptions) ([]ZeroKMSClient, error) {
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

	clients := make([]ZeroKMSClient, 0, len(*resp.JSON200))
	for _, item := range *resp.JSON200 {
		if len(item.ID) != 36 || uuid.Validate(item.ID) != nil {
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
			if len(id) != 36 || uuid.Validate(id) != nil {
				return nil, fmt.Errorf("%w: invalid client keyset UUID", ErrResponse)
			}
		}
		clients = append(clients, ZeroKMSClient{ID: item.ID, Name: item.Name, Description: *item.Description, KeysetIDs: ids})
	}
	if err := checkInventoryDuplicates(resp.Body); err != nil {
		return nil, err
	}

	return clients, nil
}

// DeleteZeroKMSClient deletes the client with the given UUID.
func (c *Client) DeleteZeroKMSClient(ctx context.Context, id string) error {
	resp, err := c.zeroKMS.DeleteClientWithResponse(ctx, zerokms.DeleteClientRequest{ClientID: id})

	return checkResponse(serviceZeroKMS, resp, err)
}
