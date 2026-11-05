package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/control"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	tonkeys "github.com/xssnick/tonutils-go/adnl/keys"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
)

type multiClient struct {
	gateway interface{ Close() error }
	peer    *roomnet.Peer
	events  chan community.CommittedEvent
}

func openMultiClient(t *testing.T, ctx context.Context, n *Node, key ed25519.PrivateKey) *multiClient {
	t.Helper()
	gateway, err := roomnet.NewGateway(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gateway.Close() })
	raw, err := gateway.DialDefault(ctx, n.cfg.Key.Public().(ed25519.PublicKey), n.cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	c := &multiClient{gateway: gateway, peer: roomnet.Wrap(raw), events: make(chan community.CommittedEvent, 16)}
	c.peer.SetMessageHandler(func(value any) error {
		wrapper, ok := broadcast.AsBroadcast(value)
		if !ok {
			return nil
		}
		event, err := community.DecodeCommittedEvent(wrapper.Data)
		if err == nil {
			c.events <- event
		}
		return err
	})
	if _, err := c.peer.ProbeCapabilities(ctx); err != nil {
		t.Fatal(err)
	}
	return c
}
func joinMultiRoom(t *testing.T, ctx context.Context, c *multiClient, g community.Genesis) {
	t.Helper()
	var result community.Genesis
	if err := c.peer.QueryRoom(ctx, g.RoomKey, community.GetRoomGenesis{}, &result); err != nil || !bytes.Equal(result.RoomKey, g.RoomKey) {
		t.Fatalf("room genesis: %v", err)
	}
}
func multiProposal(t *testing.T, g community.Genesis, key ed25519.PrivateKey, nonce byte, body any) community.EventProposal {
	t.Helper()
	n := community.Zero256()
	n[0] = nonce
	p, err := community.SignProposal(key, g.NodeKey, community.EventProposal{RoomID: g.RoomKey, Nonce: n, Timestamp: time.Now().Unix(), Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func sendMulti(t *testing.T, ctx context.Context, c *multiClient, g community.Genesis, p community.EventProposal) community.CommittedEvent {
	t.Helper()
	var result community.SubmitAccepted
	if err := c.peer.QueryRoom(ctx, g.RoomKey, community.SubmitEvent{Proposal: p}, &result); err != nil {
		t.Fatal(err)
	}
	return result.Event
}
func waitMultiCounts(t *testing.T, ctx context.Context, n *Node, a, b int) {
	t.Helper()
	for {
		status := n.Status()
		if status.Rooms[0].Members == a && status.Rooms[1].Members == b {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("room counts: %+v", status.Rooms)
		case <-time.After(time.Millisecond):
		}
	}
}
func multiConfig(t *testing.T, f *roomBindingFixture) Config {
	t.Helper()
	dir, err := os.MkdirTemp("", "tn-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return Config{Key: f.node, Listen: integrationAddress(t), Socket: filepath.Join(dir, "n.sock"), Store: f.root, LocalOnly: true, Rooms: []RoomConfig{{Genesis: &f.rooms[0].genesis, RoomKey: f.rooms[0].key}, {Genesis: &f.rooms[1].genesis, RoomKey: f.rooms[1].key}}}
}

func TestLocalMultiRoomRoutingMembershipAndManagedReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := sharedRoomBinding(t)
	cfg := multiConfig(t, f)
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	// LocalOnly Run uses the same listener and a single room-selecting control
	// handler. Public multi-room publishing is explicitly refused below.
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- n.Run(runCtx) }()
	finished := false
	defer func() {
		stop()
		if !finished {
			if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		}
	}()
	for {
		if status, err := control.Query(cfg.Socket); err == nil {
			if len(status.Rooms) != 2 {
				t.Fatal("control status omitted a room")
			}
			break
		}
		select {
		case err := <-done:
			finished = true
			t.Fatalf("LocalOnly Run failed: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	ga, gb := f.rooms[0].genesis, f.rooms[1].genesis
	identity := integrationKey(t)
	both := openMultiClient(t, ctx, n, identity)
	joinMultiRoom(t, ctx, both, ga)
	joinMultiRoom(t, ctx, both, gb)
	onlyA := openMultiClient(t, ctx, n, integrationKey(t))
	joinMultiRoom(t, ctx, onlyA, ga)
	waitMultiCounts(t, ctx, n, 2, 1)
	a := sendMulti(t, ctx, both, ga, multiProposal(t, ga, identity, 0, community.EventMessage{Text: "A"}))
	b := sendMulti(t, ctx, both, gb, multiProposal(t, gb, identity, 0, community.EventMessage{Text: "B"}))
	if a.Seqno != 1 || a.MessageID != 1 || b.Seqno != 1 || b.MessageID != 1 {
		t.Fatal("room counters/nonces did not overlap independently")
	}
	sendMulti(t, ctx, both, ga, multiProposal(t, ga, identity, 1, community.EventMessage{Text: "A marker"}))
	seen := make(map[string]map[int64]bool)
	for i := 0; i < 3; i++ {
		select {
		case event := <-both.events:
			key := string(event.Proposal.RoomID)
			if seen[key] == nil {
				seen[key] = make(map[int64]bool)
			}
			seen[key][event.Seqno] = true
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if !seen[string(ga.RoomKey)][1] || !seen[string(ga.RoomKey)][2] || !seen[string(gb.RoomKey)][1] {
		t.Fatal("shared connection lost or mixed broadcasts")
	}
	for i := 0; i < 2; i++ {
		select {
		case event := <-onlyA.events:
			if !bytes.Equal(event.Proposal.RoomID, ga.RoomKey) {
				t.Fatal("A-only member received B commit")
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	select {
	case event := <-onlyA.events:
		t.Fatalf("unexpected A-only broadcast: %x", event.Proposal.RoomID)
	case <-time.After(50 * time.Millisecond):
	}
	for i, g := range []community.Genesis{ga, gb} {
		stateQuery, _ := community.Encode(community.GetRoomState{})
		eventsQuery, _ := community.Encode(community.GetEvents{})
		var result community.BatchResult
		if err := both.peer.QueryRoom(ctx, g.RoomKey, community.Batch{Queries: [][]byte{stateQuery, eventsQuery}}, &result); err != nil || len(result.Items) != 2 {
			t.Fatalf("room batch: %+v %v", result, err)
		}
		stateAny, err := community.DecodeAny(result.Items[0].Data)
		if err != nil {
			t.Fatal(err)
		}
		state := stateAny.(community.RoomStateResult)
		eventsAny, err := community.DecodeAny(result.Items[1].Data)
		if err != nil {
			t.Fatal(err)
		}
		events := eventsAny.(community.EventList)
		want := 2 - i
		if !bytes.Equal(state.State.RoomID, g.RoomKey) || int(state.Stats.OnlineUsers) != want || len(events.Events) != want {
			t.Fatalf("cross-room state/history/presence: %+v", state)
		}
		for _, event := range events.Events {
			if !bytes.Equal(event.Proposal.RoomID, g.RoomKey) {
				t.Fatal("batch mixed room histories")
			}
		}
	}
	var rejected community.SubmitRejected
	wrong := multiProposal(t, gb, identity, 2, community.EventMessage{Text: "wrong wrapper"})
	if err := both.peer.QueryRoom(ctx, ga.RoomKey, community.SubmitEvent{Proposal: wrong}, &rejected); err != nil || rejected.Code != community.RejectWrongRoom {
		t.Fatalf("wrong room proposal: %+v %v", rejected, err)
	}
	var unavailable community.OverlayRejectedV1
	if err := both.peer.Query(ctx, community.OverlayQueryV1{Overlay: community.Zero256(), Tier: 1, Query: []byte{255}}, &unavailable); err != nil || unavailable.Code != 19 {
		t.Fatalf("unknown overlay order: %+v %v", unavailable, err)
	}
	old, _ := n.peers.get(outboundTestID(identity.Public().(ed25519.PublicKey)))
	both.gateway.Close()
	waitMultiCounts(t, ctx, n, 1, 0)
	reconnected := openMultiClient(t, ctx, n, identity)
	var remote broadcast.Time
	if err := reconnected.peer.Query(ctx, broadcast.GetTime{}, &remote); err != nil {
		t.Fatal(err)
	}
	waitMultiCounts(t, ctx, n, 1, 0)
	joinMultiRoom(t, ctx, reconnected, gb)
	waitMultiCounts(t, ctx, n, 1, 1)
	n.cleanupRoomPeer(old)
	waitMultiCounts(t, ctx, n, 1, 1) // stale cleanup is pointer-scoped.
}

func TestMultiRoomRegistrationRejectsUnsupportedOrInvalidAuthority(t *testing.T) {
	for _, mode := range []string{"public", "duplicate", "bad room key", "bad node key", "replica authority", "mixed config"} {
		t.Run(mode, func(t *testing.T) {
			f := sharedRoomBinding(t)
			bindingLegacyState(t, f, 0)
			bindingLegacyState(t, f, 1)
			beforeA, beforeB := bindingRawState(t, f, 0), bindingRawState(t, f, 1)
			cfg := multiConfig(t, f)
			switch mode {
			case "public":
				cfg.LocalOnly = false
			case "duplicate":
				cfg.Rooms[1] = cfg.Rooms[0]
			case "bad room key":
				cfg.Rooms[1].RoomKey = f.rooms[0].key
			case "bad node key":
				cfg.Key = integrationKey(t)
			case "replica authority":
				cfg.Rooms[1].NodeRole = community.NodeRoleRelay
			case "mixed config":
				cfg.Genesis = &f.rooms[0].genesis
			}
			if n, err := New(cfg); err == nil {
				n.Close()
				t.Fatal("invalid multi-room configuration accepted")
			}
			if !bytes.Equal(beforeA, bindingRawState(t, f, 0)) || !bytes.Equal(beforeB, bindingRawState(t, f, 1)) {
				t.Fatal("invalid registration converted room state")
			}
		})
	}
}

func TestRoomNodeAssociationDoesNotAuthorizeSiblingForwarding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := sharedRoomBinding(t)
	n, err := New(multiConfig(t, f))
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	key, author := integrationKey(t), integrationKey(t)
	replicaDB, err := store.Open(ctx, filepath.Join(t.TempDir(), "replica.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer replicaDB.Close()
	ga, gb := f.rooms[0].genesis, f.rooms[1].genesis
	if err := replicaDB.InitializeReplica(ctx, ga); err != nil {
		t.Fatal(err)
	}
	r, err := New(Config{Key: key, Listen: integrationAddress(t), Genesis: &ga, Store: replicaDB, NodeRole: community.NodeRoleRelay, LocalOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	p, err := r.dialNode(ctx, f.node.Public().(ed25519.PublicKey), n.cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.probeNode(ctx, p); !ok {
		t.Fatal("room-node exchange failed")
	}
	if n.Status().Rooms[0].Neighbours != 0 {
		t.Fatal("unprobed self-advertisement authorized forwarding")
	}
	back, err := n.dialNode(ctx, key.Public().(ed25519.PublicKey), r.cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := n.forRoom(n.rooms[0]).probeNode(ctx, back); !ok {
		t.Fatal("verified A association failed")
	}
	status := n.Status()
	if status.Rooms[0].Neighbours != 1 || status.Rooms[1].Neighbours != 0 || status.Rooms[1].Members != 0 {
		t.Fatalf("association escaped its room: %+v", status.Rooms)
	}
	var accepted community.SubmitAccepted
	if err := p.queryNodeRoom(ctx, ga.RoomKey, community.SubmitEvent{Proposal: multiProposal(t, ga, author, 0, community.EventMessage{Text: "forwarded A"})}, &accepted); err != nil {
		t.Fatal(err)
	}
	// Capability compatibility for A does not validate a claimed B association.
	idB, _ := community.OverlayID(gb.RoomKey)
	claim := tonoverlay.Node{ID: tonkeys.PublicKeyED25519{Key: key.Public().(ed25519.PublicKey)}, Overlay: idB, Version: int32(time.Now().Unix())}
	if err := claim.Sign(key); err != nil {
		t.Fatal(err)
	}
	var peers tonoverlay.NodesList
	if err := p.queryNodeRoom(ctx, gb.RoomKey, tonoverlay.GetRandomPeers{List: tonoverlay.NodesList{List: []tonoverlay.Node{claim}}}, &peers); err != nil {
		t.Fatal(err)
	}
	if status := n.Status(); status.Rooms[1].Neighbours != 0 || status.Rooms[1].Members != 0 {
		t.Fatal("self-advertisement transferred A authority to B")
	}
	var rejected community.SubmitRejected
	if err := p.queryNodeRoom(ctx, gb.RoomKey, community.SubmitEvent{Proposal: multiProposal(t, gb, author, 0, community.EventMessage{Text: "forged forwarding B"})}, &rejected); err != nil || rejected.Code != community.RejectPermissionDenied {
		t.Fatalf("A association authorized B: %+v %v", rejected, err)
	}
	head, err := f.rooms[1].view.Head(ctx)
	if err != nil || head.Seqno != 0 {
		t.Fatal("rejected forwarding mutated B")
	}
}

func TestMultiRoomReplicaRefreshUsesItsSelectedContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := sharedRoomBinding(t)
	remoteKey := integrationKey(t)
	roomB := integrationKey(t)
	gb, err := community.NewGenesis(roomB, remoteKey, time.Now(), "Remote B", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := f.root.ForRoom(gb.RoomKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.InitializeReplica(ctx, gb); err != nil {
		t.Fatal(err)
	}
	cfg := multiConfig(t, f)
	cfg.Rooms[1] = RoomConfig{Genesis: &gb, NodeRole: community.NodeRoleRelay}
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "remote.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Initialize(ctx, gb, roomB); err != nil {
		t.Fatal(err)
	}
	source, err := New(Config{Key: remoteKey, Listen: integrationAddress(t), Socket: filepath.Join(t.TempDir(), "node.sock"), Genesis: &gb, Store: db, RoomKey: roomB, LocalOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	p, err := n.dialNode(ctx, remoteKey.Public().(ed25519.PublicKey), source.cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := n.forRoom(n.rooms[1]).probeNode(ctx, p); !ok {
		t.Fatal("B replica source association failed")
	}
	if n.Status().Rooms[1].Ready {
		t.Fatal("unsigned replica became ready from association alone")
	}
	if err := n.reconcileReplicaOnce(); err != nil {
		t.Fatal(err)
	}
	if !n.Status().Rooms[1].Ready {
		t.Fatal("verified B snapshot not installed")
	}
	back, err := source.dialNode(ctx, f.node.Public().(ed25519.PublicKey), n.cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := source.probeNode(ctx, back); !ok {
		t.Fatal("reverse B association failed")
	}
	proposal := multiProposal(t, gb, roomB, 0, community.EventBanV1{SubjectKey: integrationKey(t).Public().(ed25519.PublicKey)})
	committed, err := source.commitProposal(ctx, proposal, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := source.broadcastCommitted(committed.Event, time.Now()); err != nil {
		t.Fatal(err)
	}
	for {
		state, err := view.State(ctx)
		if err == nil && state.RevisionSeqno == 1 && len(state.Banned) == 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("B broadcast/state refresh failed: %v", err)
		case <-time.After(time.Millisecond):
		}
	}
	if head, err := f.rooms[0].view.Head(ctx); err != nil || head.Seqno != 0 {
		t.Fatal("B refresh changed A")
	}
	if err := view.ReplicaReady(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.root.Genesis(ctx); !errors.Is(err, store.ErrAmbiguousRoom) {
		t.Fatal("root store lost its room ambiguity")
	}
}

func TestPublicMultiRoomRunFailsExplicitly(t *testing.T) {
	n := &Node{rooms: []*roomContext{{}, {}}}
	if err := n.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "public multi-room") {
		t.Fatalf("unsupported public Run was accepted: %v", err)
	}
}
