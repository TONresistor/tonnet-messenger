package replica

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

type capabilityEndpoint struct {
	genesis      community.Genesis
	state        community.RoomStateV3
	target       target
	capabilities atomic.Value
	resets       atomic.Int32
	malformed    atomic.Bool
	probes       atomic.Int32
	mu           sync.Mutex
	requests     []string
}

func capabilityKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newCapabilityEndpoint(t *testing.T) *capabilityEndpoint {
	t.Helper()
	ctx := context.Background()
	room, node := capabilityKey(t), capabilityKey(t)
	genesis, err := community.NewGenesis(room, node, time.Now(), "Capabilities", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Initialize(ctx, genesis, room); err != nil {
		t.Fatal(err)
	}
	state, err := db.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f := &capabilityEndpoint{genesis: genesis, state: state}
	f.capabilities.Store(roomnet.LocalCapabilities())
	gateway, err := roomnet.NewGateway(node)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gateway.Close() })
	id, _ := community.OverlayID(genesis.RoomKey)
	gateway.SetConnectionHandler(func(raw *quic.Peer) error {
		peer := roomnet.Wrap(raw)
		peer.SetQueryHandler(func(q *roomnet.Query) error {
			if _, ok := q.Data.(community.GetCapabilities); ok {
				f.record("capabilities")
				f.probes.Add(1)
				if f.resets.Add(-1) >= 0 {
					return roomnet.ErrNoAnswer
				}
				if f.malformed.Load() {
					return q.Answer(tl.Raw{1, 2, 3, 4})
				}
				return q.Answer(f.capabilities.Load().(community.Capabilities))
			}
			if selected, err := q.SelectOverlay(id); err != nil || !selected {
				return err
			}
			switch q.Data.(type) {
			case community.GetRoomGenesis:
				f.record("genesis")
				return q.Answer(f.genesis)
			case community.GetEvents:
				f.record("events")
				return q.Answer(community.EventList{})
			case community.GetRoomState:
				f.record("state")
				return q.Answer(community.RoomStateResult{State: f.state, Stats: community.RoomStats{NodeRole: community.NodeRoleSequencer, Ready: true}})
			default:
				return roomnet.ErrNoAnswer
			}
		})
		return nil
	})
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packet.Close() })
	go func() { _ = gateway.Serve(packet) }()
	f.target = target{address: packet.LocalAddr().String(), public: node.Public().(ed25519.PublicKey)}
	return f
}

func (f *capabilityEndpoint) record(request string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, request)
}
func (f *capabilityEndpoint) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}
func (f *capabilityEndpoint) config(t *testing.T) Config {
	return Config{RoomID: f.genesis.RoomKey, NodeKey: capabilityKey(t), DirectAddress: f.target.address, DirectPublic: f.target.public}
}

func TestAllDedicatedEntryPointsProbeBeforeRoomUse(t *testing.T) {
	for _, method := range []string{"FetchGenesis", "Sync", "DialRoom", "DialSequencer"} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			f := newCapabilityEndpoint(t)
			cfg := f.config(t)
			var session *Session
			var err error
			switch method {
			case "FetchGenesis":
				_, err = FetchGenesis(ctx, cfg)
			case "Sync":
				db, e := store.Open(ctx, filepath.Join(t.TempDir(), "replica.db"))
				if e != nil {
					t.Fatal(e)
				}
				defer db.Close()
				if e := db.InitializeReplica(ctx, f.genesis); e != nil {
					t.Fatal(e)
				}
				_, err = Sync(ctx, cfg, db)
				if err == nil {
					err = db.ReplicaReady(ctx)
				}
			case "DialRoom":
				session, err = DialRoom(ctx, cfg)
			case "DialSequencer":
				session, err = DialSequencer(ctx, cfg)
			}
			if err != nil {
				t.Fatal(err)
			}
			if session != nil {
				defer session.Close()
				if session.Capabilities != roomnet.LocalCapabilities() {
					t.Fatalf("session capabilities: %+v", session.Capabilities)
				}
				for i := 0; i < 2; i++ {
					var state community.RoomStateResult
					if err := session.Peer.QueryRoom(ctx, cfg.RoomID, community.GetRoomState{}, &state); err != nil {
						t.Fatal(err)
					}
				}
			}
			requests := f.log()
			if len(requests) < 2 || requests[0] != "capabilities" || requests[1] != "genesis" || f.probes.Load() != 1 {
				t.Fatalf("probe order or cache: %v", requests)
			}
		})
	}
}

func TestIncompatibleCapabilityCandidatesAreSkipped(t *testing.T) {
	for _, mode := range []string{"older", "malformed", "two resets"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			bad, good := newCapabilityEndpoint(t), newCapabilityEndpoint(t)
			switch mode {
			case "older":
				bad.capabilities.Store(community.Capabilities{VersionMinor: 4})
			case "malformed":
				bad.malformed.Store(true)
			case "two resets":
				bad.resets.Store(2)
			}
			connection, closeConnection, err := connectTargets(ctx, good.config(t), nil, true, []target{bad.target, good.target})
			if err != nil {
				t.Fatal(err)
			}
			defer closeConnection()
			if !bytes.Equal(connection.genesis.RoomKey, good.genesis.RoomKey) || connection.capabilities != roomnet.LocalCapabilities() {
				t.Fatal("incompatible endpoint selected")
			}
			for _, request := range bad.log() {
				if request != "capabilities" {
					t.Fatalf("incompatible endpoint used room service: %v", bad.log())
				}
			}
			want := int32(1)
			if mode == "two resets" {
				want = 2
			}
			if bad.probes.Load() != want {
				t.Fatalf("probe attempts: %d", bad.probes.Load())
			}
		})
	}
}

func TestCapabilityCacheIsDiscardedOnSameKeyReconnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := newCapabilityEndpoint(t)
	cfg := f.config(t)
	first, err := DialRoom(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	f.capabilities.Store(community.Capabilities{VersionMinor: 6, Flags: 7})
	second, err := DialRoom(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if !bytes.Equal(first.Peer.GetPubKey(), second.Peer.GetPubKey()) || second.Capabilities != (community.Capabilities{VersionMinor: 6, Flags: 6}) || first.Capabilities != roomnet.LocalCapabilities() || f.probes.Load() != 2 {
		t.Fatalf("reused stale capabilities: first=%+v second=%+v probes=%d", first.Capabilities, second.Capabilities, f.probes.Load())
	}
	// The server replaced its inbound for this key. The old dedicated client
	// loses its only connection and cannot transparently redial through Peer.
	select {
	case <-first.Done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var state community.RoomStateResult
	if err := first.Peer.QueryRoom(ctx, cfg.RoomID, community.GetRoomState{}, &state); err == nil {
		t.Fatal("closed session silently reconnected")
	}
	if f.probes.Load() != 2 {
		t.Fatal("peer silently reprobed/redialed")
	}
	second.Close()
	f.capabilities.Store(community.Capabilities{VersionMinor: 4})
	if session, err := DialRoom(ctx, cfg); !errors.Is(err, roomnet.ErrIncompatibleVersion) {
		if session != nil {
			session.Close()
		}
		t.Fatalf("changed old version accepted: %v", err)
	}
	f.capabilities.Store(community.Capabilities{VersionMajor: 1, Flags: 1})
	newer, err := DialSequencer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer newer.Close()
	if newer.Capabilities != (community.Capabilities{VersionMajor: 1}) || f.probes.Load() != 4 {
		t.Fatalf("new connection did not probe anew: %+v probes=%d", newer.Capabilities, f.probes.Load())
	}
}

func TestRejectedConnectionNeverPublishesCapabilities(t *testing.T) {
	for _, mode := range []string{"older", "malformed", "two resets"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			f := newCapabilityEndpoint(t)
			switch mode {
			case "older":
				f.capabilities.Store(community.Capabilities{VersionMinor: 4})
			case "malformed":
				f.malformed.Store(true)
			case "two resets":
				f.resets.Store(2)
			}
			cfg := f.config(t)
			session, err := DialRoom(ctx, cfg)
			if err == nil || session != nil {
				if session != nil {
					session.Close()
				}
				t.Fatalf("invalid session published: %v", err)
			}
			if mode == "older" && !errors.Is(err, roomnet.ErrIncompatibleVersion) {
				t.Fatal(err)
			}
			if mode == "malformed" && !errors.Is(err, roomnet.ErrMalformedAnswer) {
				t.Fatal(err)
			}
			if mode == "two resets" && (errors.Is(err, roomnet.ErrMalformedAnswer) || errors.Is(err, context.DeadlineExceeded)) {
				t.Fatal(fmt.Errorf("reset misclassified: %w", err))
			}
			before := f.probes.Load()
			f.resets.Store(0)
			f.malformed.Store(false)
			f.capabilities.Store(roomnet.LocalCapabilities())
			reconnected, err := DialRoom(ctx, cfg)
			if err != nil {
				t.Fatalf("later same-key connection stayed incompatible: %v", err)
			}
			defer reconnected.Close()
			if f.probes.Load() != before+1 || reconnected.Capabilities != roomnet.LocalCapabilities() {
				t.Fatal("later connection reused the rejected probe")
			}
		})
	}
}

func TestCalibrationDialPreservesUntrustedEndpointErrors(t *testing.T) {
	for _, pooled := range []bool{false, true} {
		for _, invalid := range []string{"signature", "genesis", "TLS identity"} {
			t.Run(fmt.Sprintf("pooled%v/%s", pooled, invalid), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				f := newCapabilityEndpoint(t)
				cfg := f.config(t)
				switch invalid {
				case "signature":
					f.genesis.Signature = bytes.Clone(f.genesis.Signature)
					f.genesis.Signature[0] ^= 1
				case "genesis":
					f.genesis = newCapabilityEndpoint(t).genesis
				case "TLS identity":
					cfg.DirectPublic = capabilityKey(t).Public().(ed25519.PublicKey)
				}
				if pooled {
					owner, err := NewConnector(ctx, cfg.NodeKey)
					if err != nil {
						t.Fatal(err)
					}
					defer owner.Close()
					cfg.Connector = owner
				}
				if session, err := DialSequencer(ctx, cfg); !errors.Is(err, roomnet.ErrMalformedAnswer) {
					if session != nil {
						session.Close()
					}
					t.Fatalf("untrusted endpoint became generic unavailability: %v", err)
				}
			})
		}
	}
}
