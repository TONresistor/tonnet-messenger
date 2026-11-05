package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/dht"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

// roomContext owns one room's authority and verified data. The selected store
// is a borrowed ForRoom view; the caller still owns the shared database.
// Connection identity, outbound capability lifetimes and transport limits stay
// on Node. The runtime selects a context per request.
type roomContext struct {
	genesis   community.Genesis
	overlayID []byte
	store     *store.Store
	roomKey   ed25519.PrivateKey
	role      int32

	replicaMu    sync.Mutex
	dedup        *ov.Dedup
	domainMu     sync.Mutex
	domainCache  map[string]identityDomainCache
	pub          atomic.Pointer[dht.Publisher]
	peersMu      sync.RWMutex
	associations map[*peer]roomAssociation
}

type identityDomainCache struct {
	key     []byte
	expires time.Time
}

func newRoomContext(ctx context.Context, cfg Config) (*roomContext, error) {
	r, err := bindRoomContext(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if r.role == community.NodeRoleSequencer {
		if err := r.store.UpgradeRoomState(ctx, r.roomKey); err != nil {
			return nil, fmt.Errorf("sequencer signed state upgrade: %w", err)
		}
	}
	return r, nil
}

func bindRoomContext(ctx context.Context, cfg Config) (*roomContext, error) {
	if cfg.Genesis == nil || cfg.Store == nil {
		return nil, fmt.Errorf("persistent room genesis and store are required")
	}
	genesis := cloneRoomGenesis(*cfg.Genesis)
	selected, err := cfg.Store.ForRoom(genesis.RoomKey)
	if err != nil {
		return nil, err
	}
	if err := genesis.Verify(time.Now()); err != nil {
		return nil, fmt.Errorf("invalid room genesis: %w", err)
	}
	overlayID, err := community.OverlayID(genesis.RoomKey)
	if err != nil {
		return nil, err
	}
	role := cfg.NodeRole
	if role == 0 {
		role = community.NodeRoleSequencer
	}
	if role != community.NodeRoleSequencer && role != community.NodeRoleRelay {
		return nil, fmt.Errorf("invalid node role %d", role)
	}
	if len(cfg.Key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid node identity key size")
	}
	key := ed25519.PrivateKey(bytes.Clone(cfg.RoomKey))
	if role == community.NodeRoleSequencer {
		if cfg.Socket == "" {
			return nil, fmt.Errorf("sequencer requires a control socket")
		}
		if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), genesis.RoomKey) {
			return nil, fmt.Errorf("sequencer room key does not match genesis")
		}
		if !bytes.Equal(cfg.Key.Public().(ed25519.PublicKey), genesis.NodeKey) {
			return nil, fmt.Errorf("sequencer node key does not match genesis")
		}
	} else if len(key) != 0 {
		return nil, fmt.Errorf("relay must not receive room authority key")
	}
	// Never read through the root store, even when it currently has one room.
	// Replicas validate the same explicit binding but never convert/sign state.
	if err := selected.ValidateGenesis(ctx, genesis); err != nil {
		return nil, err
	}

	return &roomContext{genesis: genesis, overlayID: overlayID, store: selected, roomKey: key, role: role, dedup: ov.NewDedup(deliveredCap), domainCache: make(map[string]identityDomainCache), associations: make(map[*peer]roomAssociation)}, nil
}

func cloneRoomGenesis(g community.Genesis) community.Genesis {
	g.RoomKey = bytes.Clone(g.RoomKey)
	g.NodeKey = bytes.Clone(g.NodeKey)
	g.Signature = bytes.Clone(g.Signature)
	admins := make([][]byte, len(g.InitialAdmins))
	for i, key := range g.InitialAdmins {
		admins[i] = bytes.Clone(key)
	}
	g.InitialAdmins = admins
	return g
}
