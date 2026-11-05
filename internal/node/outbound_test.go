package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/adnl/quic"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

type outboundProbeGate struct {
	entered, release chan struct{}
	once             sync.Once
}

func (g *outboundProbeGate) unblock() { g.once.Do(func() { close(g.release) }) }

type outboundTestEndpoint struct {
	key                      ed25519.PrivateKey
	gateway                  *quic.Gateway
	address                  string
	caps                     atomic.Value
	resets, probes, requests atomic.Int32
	gate                     atomic.Pointer[outboundProbeGate]
	messages                 chan any
}

func outboundFixture(t *testing.T) (*Node, *outboundTestEndpoint) {
	t.Helper()
	ctx := context.Background()
	room, nodeKey, remote := integrationKey(t), integrationKey(t), integrationKey(t)
	genesis, err := community.NewGenesis(room, nodeKey, time.Now(), "Outbound", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Initialize(ctx, genesis, room); err != nil {
		t.Fatal(err)
	}
	n, err := New(Config{Key: nodeKey, Listen: integrationAddress(t), Socket: filepath.Join(t.TempDir(), "node.sock"), Genesis: &genesis, RoomKey: room, Store: db})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	gateway, err := roomnet.NewGateway(remote)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gateway.Close() })
	f := &outboundTestEndpoint{key: remote, gateway: gateway, messages: make(chan any, 8)}
	f.caps.Store(roomnet.LocalCapabilities())
	state, err := db.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := community.OverlayID(genesis.RoomKey)
	gateway.SetConnectionHandler(func(raw *quic.Peer) error {
		peer := roomnet.Wrap(raw)
		peer.SetQueryHandler(func(q *roomnet.Query) error {
			if _, ok := q.Data.(community.GetCapabilities); ok {
				f.probes.Add(1)
				if f.resets.Add(-1) >= 0 {
					return roomnet.ErrNoAnswer
				}
				caps := f.caps.Load().(community.Capabilities)
				if gate := f.gate.Swap(nil); gate != nil {
					close(gate.entered)
					<-gate.release
				}
				return q.Answer(caps)
			}
			if selected, err := q.SelectOverlay(id); err != nil || !selected {
				return err
			}
			f.requests.Add(1)
			switch q.Data.(type) {
			case tonoverlay.GetRandomPeers:
				return q.Answer(tonoverlay.NodesList{})
			case community.GetRoomGenesis:
				return q.Answer(genesis)
			case community.GetRoomState:
				return q.Answer(community.RoomStateResult{State: state, Stats: community.RoomStats{Ready: true}})
			case broadcast.GetTime:
				return q.Answer(broadcast.Time{Now: 42})
			default:
				return roomnet.ErrNoAnswer
			}
		})
		peer.SetMessageHandler(func(message any) error { f.messages <- message; return nil })
		return nil
	})
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packet.Close() })
	f.address = packet.LocalAddr().String()
	go func() { _ = gateway.Serve(packet) }()
	readyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := gateway.WaitReady(readyCtx); err != nil {
		t.Fatal(err)
	}
	return n, f
}

func (f *outboundTestEndpoint) public() ed25519.PublicKey { return f.key.Public().(ed25519.PublicKey) }
func outboundTestID(public []byte) string {
	id, _ := community.KeyID(public)
	return hex.EncodeToString(id)
}
func reverseOutbound(t *testing.T, ctx context.Context, n *Node, f *outboundTestEndpoint) *peer {
	t.Helper()
	id := outboundTestID(f.public())
	n.peers.markKnown(id)
	raw, err := f.gateway.DialDefault(ctx, n.cfg.Key.Public().(ed25519.PublicKey), n.cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := community.Encode(community.GetCapabilities{})
	if _, err := raw.Query(ctx, request, roomnet.MaxAnswerObjectSize); err != nil {
		t.Fatal(err)
	}
	p, ok := n.peers.get(id)
	if !ok {
		t.Fatal("reverse peer missing")
	}
	return p
}

// A second client with the node's test identity makes the remote replace only
// its inbound. This kills the node's outbound while the reverse connection lives.
func replaceTestInbound(t *testing.T, ctx context.Context, n *Node, f *outboundTestEndpoint) {
	t.Helper()
	shadow, err := roomnet.NewGateway(n.cfg.Key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shadow.Close() })
	raw, err := shadow.DialDefault(ctx, f.public(), f.address)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := community.Encode(community.GetCapabilities{})
	// Flush a request so the server has attached the replacement connection.
	if _, err := raw.Query(ctx, request, roomnet.MaxAnswerObjectSize); err != nil {
		t.Fatal(err)
	}
}

func loseTestOutbound(t *testing.T, ctx context.Context, n *Node, f *outboundTestEndpoint, p *peer) {
	t.Helper()
	replaceTestInbound(t, ctx, n, f)
	for n.hasNodeOutbound(p) {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

func TestNodeOutboundRejectsUnprobedAndIncompatibleTraffic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n, f := outboundFixture(t)
	p := reverseOutbound(t, ctx, n, f)
	n.peers.markNodeGood(p.id, time.Now())
	var genesis community.Genesis
	if err := p.queryNodeRoom(ctx, n.genesis.RoomKey, community.GetRoomGenesis{}, &genesis); !errors.Is(err, errOutboundUnprobed) {
		t.Fatalf("unprobed query: %v", err)
	}
	if len(n.outboundTargets("", 0)) != 0 {
		t.Fatal("unprobed broadcast target selected")
	}
	if !n.enqueue(p, broadcast.Time{Now: 1}) {
		t.Fatal("could not exercise queued writer")
	}
	select {
	case <-f.messages:
		t.Fatal("unprobed node received a message")
	case <-time.After(50 * time.Millisecond):
	}
	if f.requests.Load() != 0 || f.probes.Load() != 0 {
		t.Fatal("incoming connection enabled outgoing services")
	}
	f.caps.Store(community.Capabilities{VersionMinor: 4})
	if _, err := n.dialNode(ctx, f.public(), f.address); !errors.Is(err, roomnet.ErrIncompatibleVersion) {
		t.Fatalf("old version: %v", err)
	}
	if p.outboundCaps.Load() != nil || f.requests.Load() != 0 {
		t.Fatal("incompatible peer authorized")
	}
	before := f.probes.Load()
	if _, err := n.dialNode(ctx, f.public(), f.address); !errors.Is(err, roomnet.ErrIncompatibleVersion) || f.probes.Load() != before {
		t.Fatalf("failed connection reprobed: %v", err)
	}
	n.peers.mu.RLock()
	bad, failures := p.badScore, p.failures
	n.peers.mu.RUnlock()
	if bad != 0 || failures != 0 {
		t.Fatalf("capability rejection was scored: %d %d", bad, failures)
	}
}

func TestNodeOutboundResetRetryAndBroadcast(t *testing.T) {
	for _, resets := range []int32{0, 1, 2} {
		t.Run(string(rune('0'+resets)), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			n, f := outboundFixture(t)
			f.resets.Store(resets)
			p, err := n.dialNode(ctx, f.public(), f.address)
			if resets == 2 {
				if err == nil {
					t.Fatal("two resets accepted")
				}
				p, _ = n.peers.get(outboundTestID(f.public()))
				if p.outboundCaps.Load() != nil || f.probes.Load() != 2 {
					t.Fatal("reset connection authorized")
				}
				if _, err := n.dialNode(ctx, f.public(), f.address); err == nil || f.probes.Load() != 2 {
					t.Fatal("same failed connection retried")
				}
				n.peers.mu.RLock()
				bad, failures := p.badScore, p.failures
				n.peers.mu.RUnlock()
				if bad != 0 || failures != 0 {
					t.Fatal("capability resets counted as reliability failures")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if f.probes.Load() != resets+1 {
				t.Fatal("wrong probe count")
			}
			if _, err := n.dialNode(ctx, f.public(), f.address); err != nil || f.probes.Load() != resets+1 {
				t.Fatal("live outbound was reprobed")
			}
			if _, ok := n.probeNode(ctx, p); !ok {
				t.Fatal("strict peer discovery failed")
			}
			n.keepalivePeer(ctx, p)
			var result community.RoomStateResult
			if err := p.queryNodeRoom(ctx, n.genesis.RoomKey, community.GetRoomState{}, &result); err != nil || result.State.Verify() != nil {
				t.Fatalf("strict state refresh: %v", err)
			}
			if len(n.outboundTargets("", 0)) != 1 {
				t.Fatal("compatible broadcast target missing")
			}
			proposal, err := community.SignProposal(n.roomKey, n.genesis.NodeKey, community.EventProposal{RoomID: n.genesis.RoomKey, Nonce: community.Zero256(), Timestamp: time.Now().Unix(), Body: community.EventMessage{Text: "broadcast"}})
			if err != nil {
				t.Fatal(err)
			}
			committed, err := n.store.Commit(ctx, proposal, n.roomKey, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := n.broadcastCommitted(committed.Event, time.Now()); err != nil {
				t.Fatal(err)
			}
			select {
			case message := <-f.messages:
				wrapper, ok := broadcast.AsBroadcast(message)
				if !ok || wrapper.VerifyLive(time.Now()) != nil {
					t.Fatal("invalid broadcast")
				}
				event, err := community.DecodeCommittedEvent(wrapper.Data)
				want, _ := committed.Event.Hash()
				got, _ := event.Hash()
				if err != nil || !bytes.Equal(want, got) {
					t.Fatal("broadcast changed canonical event")
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

func TestNodeOutboundLossNeverFallsBackToLiveInbound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n, f := outboundFixture(t)
	p, err := n.dialNode(ctx, f.public(), f.address)
	if err != nil {
		t.Fatal(err)
	}
	reverseOutbound(t, ctx, n, f)
	managed := n.qgw.Peer(n.cfg.Key.Public().(ed25519.PublicKey), f.public())
	// Replace the inbound with a same-key endpoint claiming an older version.
	// It must neither affect the live outbound cache nor answer node services.
	legacy, err := roomnet.NewGateway(f.key)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	var legacyProbes atomic.Int32
	legacy.SetConnectionHandler(func(raw *quic.Peer) error {
		roomnet.Wrap(raw).SetQueryHandler(func(q *roomnet.Query) error {
			if _, ok := q.Data.(community.GetCapabilities); ok {
				legacyProbes.Add(1)
				return q.Answer(community.Capabilities{VersionMinor: 4})
			}
			return q.Answer(broadcast.Time{Now: 999})
		})
		return nil
	})
	inbound, err := legacy.DialDefault(ctx, n.cfg.Key.Public().(ed25519.PublicKey), n.cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	capRequest, _ := community.Encode(community.GetCapabilities{})
	if _, err := inbound.Query(ctx, capRequest, roomnet.MaxAnswerObjectSize); err != nil {
		t.Fatal(err)
	}
	var stillOutbound broadcast.Time
	if err := p.queryNode(ctx, broadcast.GetTime{}, &stillOutbound); err != nil || stillOutbound.Now != 42 || legacyProbes.Load() != 0 {
		t.Fatalf("inbound replacement changed outgoing service: %+v %v", stillOutbound, err)
	}
	loseTestOutbound(t, ctx, n, f, p)
	if n.qgw.Peer(n.cfg.Key.Public().(ed25519.PublicKey), f.public()) != managed {
		t.Fatal("path did not survive outbound loss")
	}
	var remote broadcast.Time
	if err := p.conn.Query(ctx, broadcast.GetTime{}, &remote); err != nil || remote.Now != 999 {
		t.Fatalf("test inbound is not live: %v", err)
	}
	before := f.requests.Load()
	if err := p.queryNode(ctx, broadcast.GetTime{}, &remote); err == nil {
		t.Fatal("node query fell back to inbound")
	}
	if f.requests.Load() != before || p.outboundCaps.Load() != nil {
		t.Fatal("lost outbound used inbound or retained authorization")
	}
	if err := p.withOutbound(func(conn *roomnet.Peer) error { return conn.SendOutboundMessage(ctx, broadcast.Time{Now: 1}) }); !errors.Is(err, errOutboundUnprobed) {
		t.Fatalf("unprobed send: %v", err)
	}
	f.caps.Store(community.Capabilities{VersionMinor: 6, Flags: 7})
	replacement, err := n.dialNode(ctx, f.public(), f.address)
	if err != nil {
		t.Fatal(err)
	}
	if replacement != p || n.qgw.Peer(n.cfg.Key.Public().(ed25519.PublicKey), f.public()) != managed {
		t.Fatal("test did not reuse the same managed Peer")
	}
	if caps := p.outboundCaps.Load(); caps == nil || *caps != (community.Capabilities{VersionMinor: 6, Flags: 6}) {
		t.Fatalf("stale outbound capabilities: %+v", caps)
	}
	if err := p.queryNode(ctx, broadcast.GetTime{}, &remote); err != nil {
		t.Fatal(err)
	}
}

func TestStaleNodeProbeCannotAuthorizeReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n, f := outboundFixture(t)
	p, err := n.dialNode(ctx, f.public(), f.address)
	if err != nil {
		t.Fatal(err)
	}
	reverseOutbound(t, ctx, n, f)
	loseTestOutbound(t, ctx, n, f, p)
	gate := &outboundProbeGate{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(gate.unblock)
	f.gate.Store(gate)
	old := make(chan error, 1)
	go func() { _, err := n.dialNode(ctx, f.public(), f.address); old <- err }()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if p.outboundCaps.Load() != nil {
		t.Fatal("old authorization survived before replacement probe")
	}
	var remote broadcast.Time
	if err := p.queryNode(ctx, broadcast.GetTime{}, &remote); !errors.Is(err, errOutboundUnprobed) {
		t.Fatalf("probing connection was usable: %v", err)
	}
	f.caps.Store(community.Capabilities{VersionMinor: 4})
	newer := make(chan error, 1)
	go func() { _, err := n.dialNode(ctx, f.public(), f.address); newer <- err }()
	// Kill only the connection whose 0.5 answer is held back. The newer dial
	// waits for the older operation before it can publish its own result.
	replaceTestInbound(t, ctx, n, f)
	if err := <-old; err == nil {
		t.Fatal("closed probing connection was authorized")
	}
	if err := <-newer; !errors.Is(err, roomnet.ErrIncompatibleVersion) {
		t.Fatalf("replacement version was not checked: %v", err)
	}
	gate.unblock()
	if p.outboundCaps.Load() != nil {
		t.Fatal("stale 0.5 reply authorized the 0.4 replacement")
	}
	if _, err := n.dialNode(ctx, f.public(), f.address); !errors.Is(err, roomnet.ErrIncompatibleVersion) {
		t.Fatalf("failed replacement cache: %v", err)
	}
}
