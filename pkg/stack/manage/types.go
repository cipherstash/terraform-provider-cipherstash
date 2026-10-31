package manage

import (
	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/internal/cts"
	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/internal/zerokms"
)

// These service-qualified types alias CipherStash's generated API types.
// Their fields and pointer choices come from the overlays beside each spec.
type (
	// CreateZeroKMSKeysetOptions describes a new keyset. A nil Client creates no client.
	CreateZeroKMSKeysetOptions = zerokms.CreateKeysetOptions
	// CreateZeroKMSKeysetClientOptions requests a client alongside a new keyset.
	// ClientType must be "device", the service's supported client type.
	CreateZeroKMSKeysetClientOptions = zerokms.CreateKeysetClientOptions
	ZeroKMSClientType                = zerokms.ClientType
	// ListZeroKMSKeysetsOptions includes disabled keysets when ShowDisabled is true.
	ListZeroKMSKeysetsOptions = zerokms.ListKeysetsOptions
	// CreateZeroKMSClientOptions creates a client with an initial grant. KeysetID is
	// a UUID; empty selects the workspace's default keyset.
	CreateZeroKMSClientOptions = zerokms.CreateClientOptions

	// CTSActor is a machine identity. Its access key has a separate identifier.
	CTSActor     = cts.Actor
	CTSActorKind = cts.ActorKind
	CTSRole      = cts.Role
	// CreateCTSActorOptions describes an app or agent and its access key's role.
	// An empty Role and nil TokenExpiry (in seconds) select the service defaults.
	CreateCTSActorOptions = cts.CreateActorOptions
	// CTSActorPage is one page of actors. Pass NextCursor to the next call until it is empty.
	CTSActorPage = cts.ActorPage
	// CTSAccessKeyMetadata describes an access key without its secret.
	CTSAccessKeyMetadata = cts.AccessKeyMetadata
)
