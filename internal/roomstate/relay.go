package roomstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/keys"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

type Relay struct {
	Artifacts
	NodePrivate ed25519.PrivateKey
	Store       *store.Store
}

func LoadOrCreateRelayKey(dir string) (Paths, ed25519.PrivateKey, error) {
	paths, err := Resolve(dir)
	if err != nil {
		return Paths{}, nil, err
	}
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		return Paths{}, nil, err
	}
	if _, err := os.Stat(paths.RoomKey); err == nil {
		return Paths{}, nil, fmt.Errorf("room state: relay directory must not contain room.key")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Paths{}, nil, err
	}
	nodePrivate, err := keys.Load(paths.NodeKey)
	if errors.Is(err, os.ErrNotExist) {
		nodePrivate, err = keys.GenerateExclusive(paths.NodeKey)
	}
	if err != nil {
		return Paths{}, nil, fmt.Errorf("room state: relay node key: %w", err)
	}
	return paths, nodePrivate, nil
}

func OpenRelay(ctx context.Context, dir string, genesis community.Genesis, now time.Time) (*Relay, error) {
	paths, nodePrivate, err := LoadOrCreateRelayKey(dir)
	if err != nil {
		return nil, err
	}
	if err := genesis.Verify(now); err != nil {
		return nil, err
	}
	rawGenesis, err := EncodeGenesisArtifact(genesis)
	if err != nil {
		return nil, err
	}
	if existing, err := os.ReadFile(paths.Genesis); err == nil {
		if !bytes.Equal(existing, rawGenesis) {
			return nil, fmt.Errorf("room state: relay genesis mismatch")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := writeExclusive(paths.Genesis, rawGenesis, 0o600); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	database, err := store.Open(ctx, paths.Database)
	if err != nil {
		return nil, err
	}
	if _, _, err := database.Genesis(ctx); errors.Is(err, store.ErrNotInitialized) {
		if err := database.InitializeReplica(ctx, genesis); err != nil {
			database.Close()
			return nil, err
		}
	} else if err != nil {
		database.Close()
		return nil, err
	} else if err := database.ValidateGenesis(ctx, genesis); err != nil {
		database.Close()
		return nil, err
	}
	genesisHash, err := genesis.Hash()
	if err != nil {
		database.Close()
		return nil, err
	}
	overlayID, err := community.OverlayID(genesis.RoomKey)
	if err != nil {
		database.Close()
		return nil, err
	}
	return &Relay{
		Artifacts:   Artifacts{Paths: paths, Genesis: genesis, GenesisHash: genesisHash, OverlayID: overlayID},
		NodePrivate: nodePrivate, Store: database,
	}, nil
}
