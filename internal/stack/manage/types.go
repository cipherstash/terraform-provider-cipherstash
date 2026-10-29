package manage

import (
	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/cts"
	"github.com/cipherstash/terraform-provider-cipherstash/internal/stack/internal/zerokms"
)

// These types are generated from CipherStash's published API definitions.
// Their names and pointer choices come from the overlays beside each spec.
type (
	// CreateKeysetOptions describes a new keyset. A nil Client creates no client.
	CreateKeysetOptions = zerokms.CreateKeysetOptions
	// CreateKeysetClientOptions requests a client alongside a new keyset.
	// ClientType must be "device", the service's supported client type.
	CreateKeysetClientOptions = zerokms.CreateKeysetClientOptions
	ClientType                = zerokms.ClientType
	// ListKeysetsOptions includes disabled keysets when ShowDisabled is true.
	ListKeysetsOptions = zerokms.ListKeysetsOptions
	// CreateClientOptions creates a client with an initial grant. KeysetID is
	// a UUID; empty selects the workspace's default keyset.
	CreateClientOptions = zerokms.CreateClientOptions

	// Actor is a machine identity. Its access key has a separate identifier.
	Actor     = cts.Actor
	ActorKind = cts.ActorKind
	Role      = cts.Role
	// CreateActorOptions describes an app or agent and its access key's role.
	// An empty Role and nil TokenExpiry (in seconds) select the service defaults.
	CreateActorOptions = cts.CreateActorOptions
	// ActorPage is one page of actors. Pass NextCursor to the next call until it is empty.
	ActorPage = cts.ActorPage
	// AccessKeyMetadata describes an access key without its secret.
	AccessKeyMetadata = cts.AccessKeyMetadata
)
