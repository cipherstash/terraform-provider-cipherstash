package manage

import (
	"context"
	"fmt"
	"io"

	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/cts"
)

// CreatedActor holds the actor's metadata and its once-returned access key.
// CreatedAt is empty because CTS does not return it on creation; ListActors
// reports it. Copies share one extraction right: export the key once, or wipe it.
type CreatedActor struct {
	Actor

	Role   Role
	secret *creationSecret
}

// ExportAccessKey returns the encoded access key for persistence. The caller
// owns the bytes and should clear them after use. Later calls on this result
// or any copy return ErrSecretConsumed.
func (a *CreatedActor) ExportAccessKey() ([]byte, error) {
	if a == nil {
		return nil, ErrSecretConsumed
	}

	return a.secret.take()
}

// Wipe clears an access key that will not be exported. It is nil-safe and idempotent.
func (a *CreatedActor) Wipe() {
	if a != nil {
		a.secret.wipe()
	}
}

// Format redacts the result for every fmt verb, including in logs.
func (CreatedActor) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "manage.CreatedActor(***)") }

// CreateActor is not retried. After a transport or response error the actor
// may exist; reconcile with ListActors before creating it again.
func (c *Client) CreateActor(ctx context.Context, opts CreateActorOptions) (*CreatedActor, error) {
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

	return &CreatedActor{
		Actor:  Actor{ID: out.ActorID, Name: out.Name, Kind: out.Kind},
		Role:   out.Role,
		secret: &creationSecret{bytes: []byte(out.AccessKey)},
	}, nil
}

// ListActorsOptions selects one page. Zero Limit and empty Cursor select the
// service defaults and the first page.
type ListActorsOptions struct {
	Limit  int
	Cursor string
}

func (c *Client) ListActors(ctx context.Context, opts ListActorsOptions) (ActorPage, error) {
	var params cts.ListActorsParams
	if opts.Limit != 0 {
		params.Limit = &opts.Limit
	}

	if opts.Cursor != "" {
		params.Cursor = &opts.Cursor
	}

	resp, err := c.cts.ListActorsWithResponse(ctx, &params)
	if err := checkResponse(serviceCTS, resp, err); err != nil {
		return ActorPage{}, err
	}

	if resp.JSON200 == nil || resp.JSON200.Items == nil {
		return ActorPage{}, fmt.Errorf("%w: missing actor list", ErrResponse)
	}

	page := *resp.JSON200
	for _, actor := range page.Items {
		if actor.ID == "" || actor.Name == "" {
			return ActorPage{}, fmt.Errorf("%w: missing actor identity", ErrResponse)
		}
	}

	return page, nil
}

// DeleteActor deletes the actor and its access key. Tokens already issued for
// that key may remain usable until they expire.
func (c *Client) DeleteActor(ctx context.Context, id string) error {
	resp, err := c.cts.DeleteActorWithResponse(ctx, id, &cts.DeleteActorParams{})

	return checkResponse(serviceCTS, resp, err)
}

// ListAccessKeys returns every access key's metadata; the service does not paginate them.
func (c *Client) ListAccessKeys(ctx context.Context) ([]AccessKeyMetadata, error) {
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
