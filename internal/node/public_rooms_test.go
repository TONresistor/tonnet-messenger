package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/control"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	tonkeys "github.com/xssnick/tonutils-go/adnl/keys"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
)

// The DHT boundary is fake; all room probes and replication use real local
// authenticated QUIC peers. No advertised public address is contacted.
type fakeRoomPublisher struct {
	room             []byte
	nodes            []tonoverlay.Node
	address          string
	public           ed25519.PublicKey
	finds, resolves  atomic.Int32
	started, stopped chan struct{}
	resolveEntered   chan struct{}
}

func (p *fakeRoomPublisher) Run(ctx context.Context) {
	close(p.started)
	<-ctx.Done()
	close(p.stopped)
}
func (p *fakeRoomPublisher) FindOverlayNodes(ctx context.Context, room []byte) (*tonoverlay.NodesList, error) {
	p.finds.Add(1)
	if !bytes.Equal(room, p.room) {
		return nil, errors.New("wrong DHT room")
	}
	return &tonoverlay.NodesList{List: p.nodes}, ctx.Err()
}
func (p *fakeRoomPublisher) ResolveAll(ctx context.Context, id []byte) ([]string, ed25519.PublicKey, error) {
	p.resolves.Add(1)
	if p.resolveEntered != nil {
		close(p.resolveEntered)
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	return []string{p.address}, p.public, nil
}

func fakePublicRooms(n *Node) ([]*fakeRoomPublisher, *atomic.Int32, *atomic.Bool) {
	pubs := make([]*fakeRoomPublisher, len(n.rooms))
	for i, r := range n.rooms {
		pubs[i] = &fakeRoomPublisher{room: r.genesis.RoomKey, started: make(chan struct{}), stopped: make(chan struct{})}
	}
	closed, premature := &atomic.Int32{}, &atomic.Bool{}
	n.newPublishers = func(context.Context) ([]roomPublisher, map[string]roomPublisher, func(), error) {
		out := make([]roomPublisher, len(pubs))
		for i, p := range pubs {
			out[i] = p
		}
		all := append([]*fakeRoomPublisher(nil), pubs...)
		globals := make(map[string]roomPublisher)
		for _, overlay := range n.globalOverlays() {
			p := &fakeRoomPublisher{room: []byte(overlay.name), started: make(chan struct{}), stopped: make(chan struct{})}
			globals[overlay.name] = p
			all = append(all, p)
		}
		return out, globals, func() {
			for _, p := range all {
				select {
				case <-p.stopped:
				default:
					premature.Store(true)
				}
			}
			closed.Add(1)
		}, nil
	}
	return pubs, closed, premature
}

func runPublicNode(t *testing.T, ctx context.Context, n *Node, pubs []*fakeRoomPublisher) func() error {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var runErr error
	go func() { runErr = n.Run(ctx); close(done) }()
	stop := func() error { cancel(); <-done; return runErr }
	t.Cleanup(func() { stop() })
	for _, p := range pubs {
		select {
		case <-p.started:
		case <-done:
			t.Fatalf("Run failed: %v", runErr)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	return stop
}

func signedRoomNode(t *testing.T, key ed25519.PrivateKey, overlay []byte, version time.Time) tonoverlay.Node {
	t.Helper()
	nd := tonoverlay.Node{ID: tonkeys.PublicKeyED25519{Key: key.Public().(ed25519.PublicKey)}, Overlay: overlay, Version: int32(version.Unix())}
	if err := nd.Sign(key); err != nil {
		t.Fatal(err)
	}
	return nd
}

func TestPublicDiscoverySharesConnectionButRequiresEachRoomProof(t *testing.T) {
	for _, servesB := range []bool{true, false} {
		t.Run(map[bool]string{true: "both rooms", false: "B not served"}[servesB], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			f := sharedRoomBinding(t)
			remoteCfg := multiConfig(t, f)
			if !servesB {
				remoteCfg.Rooms = remoteCfg.Rooms[:1]
			}
			remote, err := New(remoteCfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { remote.Close() })
			root, err := store.Open(ctx, filepath.Join(t.TempDir(), "replicas.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { root.Close() })
			cfg := multiConfig(t, f)
			cfg.Key, cfg.Store, cfg.LocalOnly, cfg.Advertise = integrationKey(t), root, false, "1.1.1.1:17400"
			for i := range cfg.Rooms {
				g := f.rooms[i].genesis
				view, err := root.ForRoom(g.RoomKey)
				if err != nil {
					t.Fatal(err)
				}
				if err := view.InitializeReplica(ctx, g); err != nil {
					t.Fatal(err)
				}
				cfg.Rooms[i] = RoomConfig{Genesis: &f.rooms[i].genesis, NodeRole: community.NodeRoleRelay}
			}
			local, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { local.Close() })
			pubs, closes, premature := fakePublicRooms(local)
			for i, p := range pubs {
				p.address, p.public = remote.cfg.Listen, f.node.Public().(ed25519.PublicKey)
				p.nodes = []tonoverlay.Node{signedRoomNode(t, f.node, local.rooms[i].overlayID, time.Now())}
			}
			stop := runPublicNode(t, ctx, local, pubs)
			a, b := local.forRoom(local.rooms[0]), local.forRoom(local.rooms[1])
			// Every invalid advertisement is rejected before address resolution.
			valid := pubs[0].nodes[0]
			badSig := valid
			badSig.Signature = bytes.Clone(valid.Signature)
			badSig.Signature[0] ^= 1
			wrongKey := valid
			wrongKey.ID = tonkeys.PublicKeyED25519{Key: integrationKey(t).Public().(ed25519.PublicKey)}
			for _, nd := range []tonoverlay.Node{badSig, wrongKey, pubs[1].nodes[0], signedRoomNode(t, f.node, a.room.overlayID, time.Now().Add(-11*time.Minute)), signedRoomNode(t, f.node, a.room.overlayID, time.Now().Add(2*time.Minute))} {
				a.considerNode(ctx, &nd)
			}
			if pubs[0].resolves.Load() != 0 {
				t.Fatal("unverified advertisement reached address resolution")
			}
			a.discoverOnce(ctx)
			p, ok := local.peers.get(outboundTestID(pubs[0].public))
			if !ok || !a.peers.isHealthyNode(p) || b.peers.isHealthyNode(p) {
				t.Fatal("A proof authorized a sibling")
			}
			caps := p.outboundCaps.Load()
			b.discoverOnce(ctx)
			if b.peers.isHealthyNode(p) != servesB || !a.peers.isHealthyNode(p) || p.outboundCaps.Load() != caps || !local.outboundReady(p) {
				t.Fatal("room probe changed shared connection authorization")
			}
			if pubs[0].resolves.Load() != 1 || pubs[1].resolves.Load() != 0 || pubs[0].finds.Load() != 1 || pubs[1].finds.Load() != 1 {
				t.Fatal("room discovery did not share the authenticated endpoint")
			}
			if !servesB {
				// Also withdraw a formerly known B relationship on a scoped 19,
				// without evicting this same peer from A.
				b.peers.setNode(p, &pubs[1].nodes[0])
				if _, ok := b.probeNode(ctx, p); ok || b.peers.isHealthyNode(p) || !a.peers.isHealthyNode(p) {
					t.Fatal("B rejection retained authority or damaged A")
				}
			}
			local.peers.mu.RLock()
			failures, bad := p.failures, p.badScore
			local.peers.mu.RUnlock()
			if failures != 0 || bad != 0 {
				t.Fatal("B rejection penalized the valid A peer")
			}
			var genesis community.Genesis
			if err := p.queryNodeRoom(ctx, f.rooms[0].genesis.RoomKey, community.GetRoomGenesis{}, &genesis); err != nil {
				t.Fatal(err)
			}
			if list := a.myNodesList(); len(list.List) != 2 {
				t.Fatalf("room A self and peer missing: %d", len(list.List))
			}
			for _, nd := range b.myNodesList().List {
				if !bytes.Equal(nd.Overlay, b.room.overlayID) || nd.CheckSignature() != nil {
					t.Fatal("gossip mixed room advertisements")
				}
			}
			if err := stop(); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if closes.Load() != 1 || premature.Load() || local.publisher() != nil || b.publisher() != nil {
				t.Fatal("discovery borrowers outlived their DHT owner")
			}
		})
	}
}

func TestPublicMixedRolesReconcileInBothOrdersAndCloseCancelsDiscovery(t *testing.T) {
	for _, replicaFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "sequencer first", true: "replica first"}[replicaFirst], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			f := sharedRoomBinding(t)
			remoteKey, roomKey := integrationKey(t), integrationKey(t)
			g, err := community.NewGenesis(roomKey, remoteKey, time.Now(), "Replica", "", true, nil)
			if err != nil {
				t.Fatal(err)
			}
			remoteDB, err := store.Open(ctx, filepath.Join(t.TempDir(), "authority.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { remoteDB.Close() })
			if err := remoteDB.Initialize(ctx, g, roomKey); err != nil {
				t.Fatal(err)
			}
			remote, err := New(Config{Key: remoteKey, Listen: integrationAddress(t), Socket: filepath.Join(t.TempDir(), "unused.sock"), Genesis: &g, Store: remoteDB, RoomKey: roomKey, LocalOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { remote.Close() })
			view, err := f.root.ForRoom(g.RoomKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := view.InitializeReplica(ctx, g); err != nil {
				t.Fatal(err)
			}
			cfg := multiConfig(t, f)
			cfg.LocalOnly, cfg.Advertise = false, "1.1.1.1:17400"
			cfg.Rooms[1] = RoomConfig{Genesis: &g, NodeRole: community.NodeRoleRelay}
			if replicaFirst {
				cfg.Rooms[0], cfg.Rooms[1] = cfg.Rooms[1], cfg.Rooms[0]
			}
			n, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { n.Close() })
			p, err := n.dialNode(ctx, g.NodeKey, remote.cfg.Listen)
			if err != nil {
				t.Fatal(err)
			}
			r := n.forRoom(n.findRoom(g.RoomKey))
			if _, ok := r.probeNode(ctx, p); !ok {
				t.Fatal("replica source not selected")
			}
			if view.ReplicaReady(ctx) == nil {
				t.Fatal("association signed replica state")
			}
			pubs, closes, premature := fakePublicRooms(n)
			pubs[0].resolveEntered = make(chan struct{})
			stop := runPublicNode(t, ctx, n, pubs)
			for view.ReplicaReady(ctx) != nil {
				select {
				case <-ctx.Done():
					t.Fatal("replica loop did not start", ctx.Err())
				case <-time.After(time.Millisecond):
				}
			}
			status, err := control.Query(cfg.Socket)
			if err != nil || len(status.Rooms) != 2 {
				t.Fatalf("shared control status: %+v %v", status, err)
			}
			state, err := view.State(ctx)
			if err != nil || state.Verify() != nil || !bytes.Equal(state.RoomID, g.RoomKey) {
				t.Fatal("replica did not install verified room state")
			}
			if head, err := f.rooms[0].view.Head(ctx); err != nil || head.Seqno != 0 {
				t.Fatal("reconciliation changed sibling history")
			}
			nd := signedRoomNode(t, integrationKey(t), n.rooms[0].overlayID, time.Now())
			n.forRoom(n.rooms[0]).queueNodes([]tonoverlay.Node{nd})
			select {
			case <-pubs[0].resolveEntered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err := n.Close(); err != nil {
				t.Fatal(err)
			}
			if err := stop(); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if closes.Load() != 1 || premature.Load() {
				t.Fatal("Close did not cancel and join room discovery")
			}
			if _, err := view.Head(context.Background()); err != nil {
				t.Fatal("node closed caller-owned database")
			}
		})
	}
}

func TestRoomGossipBoundsAndPublicationStartupFailure(t *testing.T) {
	f := sharedRoomBinding(t)
	cfg := multiConfig(t, f)
	cfg.LocalOnly, cfg.Advertise = false, "1.1.1.1:17400"
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	r := n.forRoom(n.rooms[0])
	r.room.pub.Store(&roomPublication{&fakeRoomPublisher{}})
	var advertised []tonoverlay.Node
	for range maxGossipNodes + 1 {
		advertised = append(advertised, signedRoomNode(t, integrationKey(t), r.room.overlayID, time.Now()))
	}
	r.queueNodes(advertised)
	if len(r.room.advertised) != maxGossipNodes {
		t.Fatal("advertisement processing bound changed")
	}
	for i := 0; i < 10; i++ {
		nd := advertised[i]
		public := nd.ID.(tonkeys.PublicKeyED25519).Key
		id := outboundTestID(public)
		p := &peer{id: id, kind: kindNode, state: peerHealthy}
		n.peers.m[id] = p
		r.peers.setNode(p, &nd)
	}
	list := r.myNodesList()
	if len(list.List) != 8 || !list.List[0].ID.(tonkeys.PublicKeyED25519).Key.Equal(f.node.Public()) {
		t.Fatal("gossip answer is not self plus seven")
	}
	for _, nd := range list.List {
		if nd.CheckSignature() != nil || !bytes.Equal(nd.Overlay, r.room.overlayID) {
			t.Fatal("gossip answer has invalid room node")
		}
	}
	// No real DHT request is needed to prove that initialization failure tears
	// down the already-started single control service.
	n.newPublishers = func(context.Context) ([]roomPublisher, map[string]roomPublisher, func(), error) {
		return nil, nil, nil, errors.New("DHT initialization failed")
	}
	if err := n.Run(context.Background()); err == nil {
		t.Fatal("failed DHT startup was accepted")
	}
	if _, err := control.Query(cfg.Socket); err == nil {
		t.Fatal("failed startup left control service running")
	}
}
