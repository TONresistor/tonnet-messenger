package replica

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	tondht "github.com/xssnick/tonutils-go/adnl/dht"
	tonkeys "github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	messengerdht "github.com/TONresistor/tonnet-messenger/internal/dht"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
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
	client, closeClient, err := connect(ctx, cfg, nil, true)
	if err != nil {
		return community.Genesis{}, err
	}
	defer closeClient()
	return client.genesis, nil
}

func Sync(ctx context.Context, cfg Config, database *store.Store) (Result, error) {
	client, closeClient, err := connect(ctx, cfg, database, true)
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
		err := client.peer.Query(queryCtx, community.GetEvents{AfterSeqno: head.Seqno, Limit: community.MaxPageLimit}, &page)
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
	err = client.peer.Query(stateCtx, community.GetRoomState{}, &stateResult)
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
	peer    *roomnet.Peer
	done    <-chan struct{}
}

type Session struct {
	Genesis community.Genesis
	Peer    *roomnet.Peer
	Done    <-chan struct{}
	close   func()
}

func DialSequencer(ctx context.Context, cfg Config) (*Session, error) {
	return dialRoom(ctx, cfg, true)
}

func DialRoom(ctx context.Context, cfg Config) (*Session, error) {
	return dialRoom(ctx, cfg, false)
}

func dialRoom(ctx context.Context, cfg Config, requireSequencer bool) (*Session, error) {
	connected, closeSession, err := connect(ctx, cfg, nil, requireSequencer)
	if err != nil {
		return nil, err
	}
	return &Session{Genesis: connected.genesis, Peer: connected.peer, Done: connected.done, close: closeSession}, nil
}

func (s *Session) Close() {
	if s != nil && s.close != nil {
		s.close()
		s.close = nil
	}
}

func connect(ctx context.Context, cfg Config, database *store.Store, requireSequencer bool) (*connected, func(), error) {
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
	gateway, err := roomnet.NewGateway(cfg.NodeKey)
	if err != nil {
		return nil, nil, err
	}
	closeClient := func() { gateway.Close() }
	for _, candidate := range targets {
		peer, err := gateway.DialDefault(ctx, candidate.public, candidate.address)
		if err != nil {
			continue
		}
		wrapper := roomnet.Wrap(peer)
		var genesis community.Genesis
		queryCtx, queryCancel := context.WithTimeout(ctx, 5*time.Second)
		queryErr := wrapper.Query(queryCtx, community.GetRoomGenesis{}, &genesis)
		queryCancel()
		if queryErr != nil || genesis.Verify(time.Now()) != nil || !bytes.Equal(genesis.RoomKey, cfg.RoomID) ||
			(requireSequencer && !bytes.Equal(genesis.NodeKey, candidate.public)) {
			peer.Close()
			continue
		}
		if database != nil {
			if err := database.ValidateGenesis(ctx, genesis); err != nil {
				peer.Close()
				continue
			}
		}
		return &connected{genesis: genesis, peer: wrapper, done: wrapper.Done()}, closeClient, nil
	}
	closeClient()
	if !requireSequencer {
		return nil, nil, fmt.Errorf("replica: no live room endpoint")
	}
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
		resolvedID, err := community.KeyID(public)
		if err != nil || !bytes.Equal(resolvedID, id) {
			continue
		}
		for _, candidate := range addresses.Addresses {
			switch candidate.(type) {
			case address.QUIC, *address.QUIC:
			default:
				continue
			}
			ip := address.IPValue(candidate)
			port := address.PortValue(candidate)
			if !messengerdht.PublicADNLIP(ip) || port <= 0 {
				continue
			}
			targets = append(targets, target{
				address: net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), public: public,
			})
		}
	}
	rand.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
	if len(targets) > 16 {
		targets = targets[:16]
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("replica: no dialable TON QUIC room nodes")
	}
	return targets, nil
}
