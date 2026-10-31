package manage

import (
	"context"
	"fmt"
	"io"

	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/internal/cts"
)

// CreatedCTSActor holds the actor's metadata and its once-returned access key.
// CreatedAt is empty because CTS does not return it on creation; ListCTSActors
// reports it. Copies share one extraction right: export the key once, or wipe it.
type CreatedCTSActor struct {
	CTSActor

	Role   CTSRole
	secret *creationSecret
}

// ExportAccessKey returns the encoded access key for persistence. The caller
// owns the bytes and should clear them after use. Later calls on this result
// or any copy return ErrSecretConsumed.
func (a *CreatedCTSActor) ExportAccessKey() ([]byte, error) {
	if a == nil {
		return nil, ErrSecretConsumed
	}

	return a.secret.take()
}

// Wipe clears an access key that will not be exported. It is nil-safe and idempotent.
func (a *CreatedCTSActor) Wipe() {
	if a != nil {
		a.secret.wipe()
	}
}

// Format redacts the result for every fmt verb, including in logs.
func (CreatedCTSActor) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "manage.CreatedCTSActor(***)")
}

// CreateCTSActor is not retried. After a transport or response error the actor
// may exist; reconcile with ListCTSActors before creating it again.
func (c *Client) CreateCTSActor(ctx context.Context, opts CreateCTSActorOptions) (*CreatedCTSActor, error) {
	resp, err := c.cts.CreateActorWithResponse(ctx, opts)
	if err := checkResponse(serviceCTS, resp, err); err != nil {
		return nil, err
	}
	// The body contains the access key.
	defer clear(resp.Body)
	out := resp.JSON201
	if out == nil || out.ActorID == "" || out.Name == "" || out.Kind == "" || out.Role == "" || out.AccessKey == "" {
		return nil, fmt.Errorf("%w: incomplete create-actor response", ErrResponse)
	}

	return &CreatedCTSActor{
		ID:     out.ActorID,
		Name:   out.Name,
		Kind:   out.Kind,
		Role:   out.Role,
		secret: &creationSecret{bytes: []byte(out.AccessKey)},
	}, nil
}

// ListCTSActorsOptions selects one page. Zero Limit and empty Cursor select the
// service defaults and the first page.
type ListCTSActorsOptions struct {
	Limit  int
	Cursor string
}

func (c *Client) ListCTSActors(ctx context.Context, opts ListCTSActorsOptions) (CTSActorPage, error) {
	var params cts.ListActorsParams
	if opts.Limit != 0 {
		params.Limit = &opts.Limit
	}
	if opts.Cursor != "" {
		params.Cursor = &opts.Cursor
	}
	resp, err := c.cts.ListActorsWithResponse(ctx, &params)
	if err := checkResponse(serviceCTS, resp, err); err != nil {
		return CTSActorPage{}, err
	}
	if resp.JSON200 == nil || resp.JSON200.Items == nil {
		return CTSActorPage{}, fmt.Errorf("%w: missing actor list", ErrResponse)
	}
	page := *resp.JSON200
	for _, actor := range page.Items {
		if actor.ID == "" || actor.Name == "" {
			return CTSActorPage{}, fmt.Errorf("%w: missing actor identity", ErrResponse)
		}
	}

	return page, nil
}

// DeleteCTSActor deletes the actor and its access key. Tokens already issued for
// that key may remain usable until they expire.
func (c *Client) DeleteCTSActor(ctx context.Context, id string) error {
	resp, err := c.cts.DeleteActorWithResponse(ctx, id, &cts.DeleteActorParams{})

	return checkResponse(serviceCTS, resp, err)
}

// ListCTSAccessKeys returns every access key's metadata; the service does not paginate them.
func (c *Client) ListCTSAccessKeys(ctx context.Context) ([]CTSAccessKeyMetadata, error) {
	resp, err := c.cts.ListAccessKeysWithResponse(ctx, &cts.ListAccessKeysParams{})
	if err := checkResponse(serviceCTS, resp, err); err != nil {
		return nil, err
	}
	// A missing or null inventory is malformed; an empty array is not.
	if resp.JSON200 == nil || *resp.JSON200 == nil {
		return nil, fmt.Errorf("%w: missing access-key list", ErrResponse)
	}
	keys := *resp.JSON200
	for _, key := range keys {
		if key.ID == "" || key.Name == "" {
			return nil, fmt.Errorf("%w: missing access-key identity", ErrResponse)
		}
	}

	return keys, nil
}
