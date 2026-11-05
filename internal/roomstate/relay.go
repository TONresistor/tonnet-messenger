package roomstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/keys"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

type Relay struct {
	Artifacts
	NodePrivate ed25519.PrivateKey
	Store       *store.Store
	owner       *NodeState
}

func (r *Relay) Close() error { return r.owner.Close() }

func LoadOrCreateRelayKey(dir string) (Paths, ed25519.PrivateKey, error) {
	paths, err := Resolve(dir)
	if err != nil {
		return Paths{}, nil, err
	}
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		return Paths{}, nil, err
	}
	if err := realDirectory(paths.Dir); err != nil {
		return Paths{}, nil, err
	}
	if err := regularFile(paths.NodeKey); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Paths{}, nil, err
	}
	nodePrivate, err := keys.Load(paths.NodeKey)
	if errors.Is(err, os.ErrNotExist) {
		for _, artifact := range []string{paths.RoomKey, paths.Genesis, paths.Database, filepath.Join(paths.Dir, "rooms")} {
			if _, err := os.Lstat(artifact); err == nil {
				return Paths{}, nil, fmt.Errorf("room state: existing state is missing node.key")
			} else if !errors.Is(err, os.ErrNotExist) {
				return Paths{}, nil, err
			}
		}
		nodePrivate, err = keys.GenerateExclusive(paths.NodeKey)
	}
	if err != nil {
		return Paths{}, nil, fmt.Errorf("room state: relay node key: %w", err)
	}
	return paths, nodePrivate, nil
}

func OpenRelay(ctx context.Context, dir string, genesis community.Genesis, now time.Time) (*Relay, error) {
	if err := genesis.Verify(now); err != nil {
		return nil, err
	}
	paths, _, err := LoadOrCreateRelayKey(dir)
	if err != nil {
		return nil, err
	}
	rawGenesis, err := EncodeGenesisArtifact(genesis)
	if err != nil {
		return nil, err
	}
	if existing, err := os.ReadFile(paths.Genesis); err == nil {
		stored, err := LoadGenesis(paths.Genesis, now)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(stored.RoomKey, genesis.RoomKey) {
			if !bytes.Equal(existing, rawGenesis) {
				return nil, fmt.Errorf("%w: relay genesis mismatch", store.ErrGenesisMismatch)
			}
		} else {
			// Existing shared state: create a new public-only room artifact, or
			// validate an already retained one without replacing its bytes.
			selected, err := additionalPaths(paths, genesis.RoomKey)
			if err != nil {
				return nil, err
			}
			if _, err := os.Lstat(selected.Genesis); errors.Is(err, os.ErrNotExist) {
				if _, err := RetainReplica(ctx, dir, genesis, now); err != nil {
					return nil, err
				}
			} else if err != nil {
				return nil, err
			}
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if _, err := os.Lstat(paths.RoomKey); err == nil {
			return nil, fmt.Errorf("room state: existing authority is missing genesis")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := writeExclusive(paths.Genesis, rawGenesis, 0o600); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	artifacts, err := selectedArtifacts(paths, genesis.RoomKey, now)
	if err != nil {
		return nil, err
	}
	expectedHash, err := genesis.Hash()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(artifacts.GenesisHash, expectedHash) {
		return nil, store.ErrGenesisMismatch
	}
	if _, err := os.Lstat(artifacts.Paths.RoomKey); err == nil {
		return nil, fmt.Errorf("room state: replica artifact contains room authority")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	database, err := store.Open(ctx, paths.Database)
	if err != nil {
		return nil, err
	}
	view, err := database.ForRoom(genesis.RoomKey)
	if err != nil {
		database.Close()
		return nil, err
	}
	if _, _, err := view.Genesis(ctx); errors.Is(err, store.ErrNotInitialized) {
		if err := view.InitializeReplica(ctx, genesis); err != nil {
			database.Close()
			return nil, err
		}
	} else if err != nil {
		database.Close()
		return nil, err
	} else if err := view.ValidateGenesis(ctx, genesis); err != nil {
		database.Close()
		return nil, err
	}
	if err := database.Close(); err != nil {
		return nil, err
	}
	n, err := LoadRooms(ctx, dir, []Selection{{RoomID: genesis.RoomKey, Role: community.NodeRoleRelay}}, now)
	if err != nil {
		return nil, err
	}
	r := n.Rooms[0]
	if err := r.Store.ValidateGenesis(ctx, genesis); err != nil {
		n.Close()
		return nil, err
	}
	return &Relay{
		Artifacts:   r.Artifacts,
		NodePrivate: n.NodePrivate, Store: r.Store, owner: n,
	}, nil
}
