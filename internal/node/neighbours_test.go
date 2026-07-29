package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"
)

type recordingPeer struct {
	id      []byte
	addr    string
	pingErr error

	closes   atomic.Int32
	customs  atomic.Int32
	queries  atomic.Int32
	pings    atomic.Int32
	register atomic.Int32
}

func (p *recordingPeer) SetCustomMessageHandler(func(*adnl.MessageCustom) error) { p.customs.Add(1) }
func (p *recordingPeer) SetQueryHandler(func(*adnl.MessageQuery) error)          { p.queries.Add(1) }
func (p *recordingPeer) GetDisconnectHandler() func(string, ed25519.PublicKey)   { return nil }
func (p *recordingPeer) SetDisconnectHandler(func(string, ed25519.PublicKey))    {}
func (p *recordingPeer) SendCustomMessage(context.Context, tl.Serializable) error {
	return nil
}
func (p *recordingPeer) Query(context.Context, tl.Serializable, tl.Serializable) error {
	return errors.New("no query")
}
func (p *recordingPeer) Answer(context.Context, []byte, tl.Serializable) error { return nil }
func (p *recordingPeer) Ping(context.Context) (time.Duration, error) {
	p.pings.Add(1)
	return 0, p.pingErr
}
func (p *recordingPeer) GetQueryHandler() func(*adnl.MessageQuery) error { return nil }
func (p *recordingPeer) GetCloserCtx() context.Context                   { return context.Background() }
func (p *recordingPeer) SetAddresses(address.List)                       {}
func (p *recordingPeer) RemoteAddr() string                              { return p.addr }
func (p *recordingPeer) GetID() []byte                                   { return append([]byte(nil), p.id...) }
func (p *recordingPeer) GetPubKey() ed25519.PublicKey                    { return nil }
func (p *recordingPeer) Reinit()                                         {}
func (p *recordingPeer) Close()                                          { p.closes.Add(1) }

func TestPickLiveAddrDoesNotCloseFailedPings(t *testing.T) {
	dead := &recordingPeer{id: []byte("dead"), addr: "1.1.1.1:1", pingErr: errors.New("timeout")}
	live := &recordingPeer{id: []byte("live"), addr: "2.2.2.2:2"}
	peers := []adnl.Peer{dead, live}
	var i int
	peer, addr, reused, ok := pickLiveAddr(context.Background(), []string{"1.1.1.1:1", "2.2.2.2:2"},
		func() adnl.Peer { return nil },
		func() bool { return false },
		func(string) (adnl.Peer, error) {
			p := peers[i]
			i++
			return p, nil
		},
	)
	if !ok || reused || peer != live || addr != "2.2.2.2:2" {
		t.Fatalf("want the second live address, got ok=%v reused=%v addr=%s", ok, reused, addr)
	}
	if dead.closes.Load() != 0 || live.closes.Load() != 0 {
		t.Fatalf("failed pings must not Close the ADNL session (dead=%d live=%d)", dead.closes.Load(), live.closes.Load())
	}
	if dead.pings.Load() != 1 || live.pings.Load() != 1 {
		t.Fatal("each candidate should be pinged once")
	}
}

func TestPickLiveAddrReusesExistingGatewayPeer(t *testing.T) {
	existing := &recordingPeer{id: []byte("id"), addr: "9.9.9.9:9"}
	registers := 0
	peer, addr, reused, ok := pickLiveAddr(context.Background(), []string{"1.1.1.1:1"},
		func() adnl.Peer { return existing },
		func() bool { return false },
		func(string) (adnl.Peer, error) {
			registers++
			return &recordingPeer{addr: "1.1.1.1:1"}, nil
		},
	)
	if !ok || !reused || peer != existing || addr != "9.9.9.9:9" {
		t.Fatalf("want the existing gateway peer, got ok=%v reused=%v addr=%s", ok, reused, addr)
	}
	if registers != 0 {
		t.Fatalf("RegisterClient must not retarget a live session, got %d calls", registers)
	}
	if existing.closes.Load() != 0 || existing.pings.Load() != 0 {
		t.Fatal("an existing gateway peer must not be ping-probed or closed")
	}
}

func TestPickLiveAddrTreatsTrackedPeerAsReused(t *testing.T) {
	p := &recordingPeer{id: []byte("id"), addr: "1.1.1.1:1"}
	peer, _, reused, ok := pickLiveAddr(context.Background(), []string{"1.1.1.1:1"},
		func() adnl.Peer { return nil },
		func() bool { return true },
		func(string) (adnl.Peer, error) { return p, nil },
	)
	if !ok || !reused || peer != nil {
		t.Fatalf("a tracked Tonnet peer must short-circuit as reused, got ok=%v reused=%v peer=%v", ok, reused, peer)
	}
	if p.closes.Load() != 0 || p.pings.Load() != 0 {
		t.Fatal("tracked peers must not be pinged or closed")
	}
}

func TestCompleteMeshDoesNotRewrapTrackedPeer(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	id := "aabb"
	raw := &recordingPeer{id: []byte(id), addr: "1.1.1.1:1"}
	existing, created := n.peers.addNode(id, &tonoverlay.ADNLOverlayWrapper{}, raw, nil)
	if !created || existing == nil {
		t.Fatal("setup: node should be tracked")
	}
	handlersBefore := raw.customs.Load() + raw.queries.Load()

	n.completeMesh(context.Background(), id, raw, raw.addr, nil)

	if raw.closes.Load() != 0 {
		t.Fatal("completeMesh must not Close an already-tracked session")
	}
	if raw.customs.Load()+raw.queries.Load() != handlersBefore {
		t.Fatal("CreateExtendedADNL must not run again on a tracked peer")
	}
	got, ok := n.peers.get(id)
	if !ok || got != existing || got.w == nil {
		t.Fatal("tracked overlay wrapper must be left in place")
	}
}

func TestCompleteMeshWiresOnlyNewlyCreatedNode(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	n.devices = newDeviceTable()
	id := "ccdd"
	raw := &recordingPeer{id: []byte(id), addr: "3.3.3.3:3"}

	n.completeMesh(context.Background(), id, raw, raw.addr, nil)

	p, ok := n.peers.get(id)
	if !ok || p == nil || p.kind != kindNode {
		t.Fatal("a new mesh session must be added as a node peer")
	}
	if p.w == nil {
		t.Fatal("a newly created node must get an overlay wrapper")
	}
	if raw.customs.Load() == 0 || raw.queries.Load() == 0 {
		t.Fatal("CreateExtendedADNL must install overlay handlers on a new session")
	}
	if raw.closes.Load() != 0 {
		t.Fatal("completeMesh must not Close the session it just wired")
	}
	n.closePeer(p, "test cleanup")
}

func TestAlreadyMeshedMarksKnownWithoutDialing(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	id := "eeff"
	if n.alreadyMeshed(id, []byte{1, 2, 3}, nil) {
		t.Fatal("absent peer and gateway must not look meshed")
	}
	n.peers.addNode(id, nil, nil, nil)
	if !n.alreadyMeshed(id, []byte{1, 2, 3}, nil) {
		t.Fatal("a tracked node must count as already meshed")
	}
}
