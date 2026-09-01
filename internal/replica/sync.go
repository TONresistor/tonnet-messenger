package replica

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	tondht "github.com/xssnick/tonutils-go/adnl/dht"
	tonkeys "github.com/xssnick/tonutils-go/adnl/keys"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	messengerdht "github.com/TONresistor/tonnet-messenger/internal/dht"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

type Config struct {
	ConfigURL     string
	RoomID        []byte
	NodeKey       ed25519.PrivateKey
	BootstrapADNL []byte
	DirectAddress string
	DirectPublic  ed25519.PublicKey
}

type Result struct {
	Genesis community.Genesis
	State   community.RoomState
	Head    store.Head
}

type target struct {
	address string
	public  ed25519.PublicKey
}

func FetchGenesis(ctx context.Context, cfg Config) (community.Genesis, error) {
	client, closeClient, err := connect(ctx, cfg, nil)
	if err != nil {
		return community.Genesis{}, err
	}
	defer closeClient()
	return client.genesis, nil
}

func Sync(ctx context.Context, cfg Config, database *store.Store) (Result, error) {
	client, closeClient, err := connect(ctx, cfg, database)
	if err != nil {
		return Result{}, err
	}
	defer closeClient()
	head, err := database.Head(ctx)
	if err != nil {
		return Result{}, err
	}
	for {
		var page community.EventList
		queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := client.overlay.Query(queryCtx, community.GetEvents{AfterSeqno: head.Seqno, Limit: community.MaxPageLimit}, &page)
		cancel()
		if err != nil {
			return Result{}, fmt.Errorf("replica: get events after %d: %w", head.Seqno, err)
		}
		for _, event := range page.Events {
			if _, err := database.AppendReplica(ctx, event); err != nil {
				return Result{}, err
			}
			head, err = database.Head(ctx)
			if err != nil {
				return Result{}, err
			}
		}
		if !page.HasMore {
			break
		}
		if len(page.Events) == 0 {
			return Result{}, fmt.Errorf("replica: sequencer returned empty page with has_more")
		}
	}
	var stateResult community.RoomStateResult
	stateCtx, stateCancel := context.WithTimeout(ctx, 10*time.Second)
	err = client.overlay.Query(stateCtx, community.GetRoomState{}, &stateResult)
	stateCancel()
	if err != nil {
		return Result{}, fmt.Errorf("replica: get room state: %w", err)
	}
	if stateResult.Stats.NodeRole != community.NodeRoleSequencer || !stateResult.Stats.Ready {
		return Result{}, fmt.Errorf("replica: bootstrap endpoint is not a ready sequencer")
	}
	if err := database.InstallReplicaState(ctx, stateResult.State); err != nil {
		return Result{}, err
	}
	if err := database.ReplicaReady(ctx); err != nil {
		return Result{}, err
	}
	if err := database.Audit(ctx); err != nil {
		return Result{}, fmt.Errorf("replica: database audit: %w", err)
	}
	head, err = database.Head(ctx)
	if err != nil {
		return Result{}, err
	}
	return Result{Genesis: client.genesis, State: stateResult.State, Head: head}, nil
}

type connected struct {
	genesis community.Genesis
	overlay *tonoverlay.ADNLOverlayWrapper
	done    <-chan struct{}
}

type Session struct {
	Genesis community.Genesis
	Overlay *tonoverlay.ADNLOverlayWrapper
	Done    <-chan struct{}
	close   func()
}

func DialSequencer(ctx context.Context, cfg Config) (*Session, error) {
	connected, closeSession, err := connect(ctx, cfg, nil)
	if err != nil {
		return nil, err
	}
	return &Session{Genesis: connected.genesis, Overlay: connected.overlay, Done: connected.done, close: closeSession}, nil
}

func (s *Session) Close() {
	if s != nil && s.close != nil {
		s.close()
		s.close = nil
	}
}

func connect(ctx context.Context, cfg Config, database *store.Store) (*connected, func(), error) {
	if len(cfg.RoomID) != ed25519.PublicKeySize || len(cfg.NodeKey) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("replica: invalid room or node key")
	}
	var targets []target
	if cfg.DirectAddress != "" {
		if len(cfg.DirectPublic) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("replica: direct target requires an Ed25519 public key")
		}
		targets = []target{{address: cfg.DirectAddress, public: append(ed25519.PublicKey(nil), cfg.DirectPublic...)}}
	} else {
		_, ephemeral, err := ed25519.GenerateKey(cryptorand.Reader)
		if err != nil {
			return nil, nil, err
		}
		discoveryGateway := adnl.NewGateway(ephemeral)
		if err := discoveryGateway.StartClient(); err != nil {
			return nil, nil, err
		}
		dhtClient, err := tondht.NewClientFromConfigUrl(ctx, discoveryGateway, cfg.ConfigURL)
		if err != nil {
			discoveryGateway.Close()
			return nil, nil, err
		}
		targets, err = resolveTargets(ctx, dhtClient, cfg.RoomID, cfg.BootstrapADNL)
		discoveryGateway.Close()
		if err != nil {
			return nil, nil, err
		}
	}
	gateway := adnl.NewGateway(cfg.NodeKey)
	if err := gateway.StartClient(); err != nil {
		return nil, nil, err
	}
	closeClient := func() { gateway.Close() }
	overlayID, err := community.OverlayID(cfg.RoomID)
	if err != nil {
		closeClient()
		return nil, nil, err
	}
	for _, candidate := range targets {
		peer, err := gateway.RegisterClient(candidate.address, candidate.public)
		if err != nil {
			continue
		}
		pingCtx, pingCancel := context.WithTimeout(ctx, 3*time.Second)
		_, pingErr := peer.Ping(pingCtx)
		pingCancel()
		if pingErr != nil {
			peer.Close()
			continue
		}
		wrapper := tonoverlay.CreateExtendedADNL(peer).WithOverlay(overlayID)
		var genesis community.Genesis
		queryCtx, queryCancel := context.WithTimeout(ctx, 5*time.Second)
		queryErr := wrapper.Query(queryCtx, community.GetRoomGenesis{}, &genesis)
		queryCancel()
		if queryErr != nil || genesis.Verify(time.Now()) != nil || !bytes.Equal(genesis.RoomKey, cfg.RoomID) || !bytes.Equal(genesis.NodeKey, candidate.public) {
			peer.Close()
			continue
		}
		if database != nil {
			if err := database.ValidateGenesis(ctx, genesis); err != nil {
				peer.Close()
				continue
			}
		}
		return &connected{genesis: genesis, overlay: wrapper, done: peer.GetCloserCtx().Done()}, closeClient, nil
	}
	closeClient()
	return nil, nil, fmt.Errorf("replica: no live authoritative endpoint")
}

func resolveTargets(ctx context.Context, dhtClient *tondht.Client, roomID, bootstrapADNL []byte) ([]target, error) {
	var ids [][]byte
	if len(bootstrapADNL) > 0 {
		ids = append(ids, bootstrapADNL)
	} else {
		list, _, err := dhtClient.FindOverlayNodes(ctx, roomID)
		if err != nil {
			return nil, err
		}
		if list == nil {
			return nil, fmt.Errorf("replica: no room nodes in DHT")
		}
		for _, node := range messengerdht.FilterOverlayNodes(list.List, roomID, time.Now()) {
			public, ok := node.ID.(tonkeys.PublicKeyED25519)
			if !ok || len(public.Key) != ed25519.PublicKeySize {
				continue
			}
			id, err := tl.Hash(node.ID)
			if err == nil {
				ids = append(ids, id)
			}
		}
	}
	var targets []target
	for _, id := range ids {
		addresses, public, err := dhtClient.FindAddresses(ctx, id)
		if err != nil || addresses == nil || len(public) != ed25519.PublicKeySize {
			continue
		}
		for _, candidate := range addresses.Addresses {
			if !messengerdht.PublicADNLIP(address.IPValue(candidate)) {
				continue
			}
			dialAddress, err := address.DialString(candidate)
			if err == nil {
				targets = append(targets, target{address: dialAddress, public: public})
			}
		}
	}
	rand.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
	if len(targets) > 16 {
		targets = targets[:16]
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("replica: no dialable room nodes")
	}
	return targets, nil
}
