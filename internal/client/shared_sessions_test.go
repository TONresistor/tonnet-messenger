package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/node"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	"github.com/xssnick/tonutils-go/adnl/quic"
)

func sharedAddress(t *testing.T) string {
	t.Helper()
	p, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := p.LocalAddr().String()
	p.Close()
	return address
}

func openSharedClient(t *testing.T, ctx context.Context, address string, public ed25519.PublicKey) (*Client, <-chan Notification) {
	t.Helper()
	c, err := Open(ctx, Config{StateDir: t.TempDir(), DirectAddress: address, DirectPublic: public})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	events := make(chan Notification, 64)
	go func() {
		defer close(events)
		for n := range c.Notifications() {
			if n.Method == "room.event" || n.Method == "dm.message" {
				select {
				case events <- n:
				case <-ctx.Done():
				}
			}
		}
	}()
	return c, events
}

func joinSharedRooms(t *testing.T, ctx context.Context, c *Client, rooms []community.Genesis) {
	t.Helper()
	errors := make(chan error, len(rooms))
	for _, g := range rooms {
		go func() { _, err := c.Join(ctx, keyText(g.RoomKey), nil); errors <- err }()
	}
	for range rooms {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
}

func sharedSession(c *Client, key []byte) *replica.Session {
	c.mu.RLock()
	r := c.rooms[keyText(key)]
	c.mu.RUnlock()
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.session
}

func waitSharedConnection(t *testing.T, ctx context.Context, c *Client, rooms []community.Genesis, old *roomnet.Peer) *roomnet.Peer {
	t.Helper()
	for {
		var peer *roomnet.Peer
		ready := true
		for _, g := range rooms {
			s := sharedSession(c, g.RoomKey)
			if s == nil || s.Peer == old || (peer != nil && s.Peer != peer) {
				ready = false
				break
			}
			select {
			case <-s.Done:
				ready = false
			default:
			}
			peer = s.Peer
		}
		if ready {
			return peer
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func expectSharedEvent(t *testing.T, ctx context.Context, c *Client, events <-chan Notification, room []byte, text string) {
	t.Helper()
	select {
	case n := <-events:
		v, ok := n.Params.(map[string]any)
		if !ok || n.Method != "room.event" || v["room"] != keyText(room) || v["text"] != text {
			t.Fatalf("wrong room event: %#v", n)
		}
		// A notification is usable only after its verified event is durable.
		history, _, err := c.store.timeline(ctx, room, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, event := range history {
			id, _ := event.Proposal.ID()
			if keyText(id) == v["event_id"] && event.Verify(room, sharedSession(c, room).Genesis.NodeKey) == nil {
				found = true
			}
		}
		if !found {
			t.Fatal("notification preceded verified durable history")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestClientSharesMultiRoomConnectionAcrossLeaveLossAndIdentityReset(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	nodeKey := clientTestPrivateKey(t)
	root, err := store.Open(ctx, filepath.Join(t.TempDir(), "rooms.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	address := sharedAddress(t)
	public := nodeKey.Public().(ed25519.PublicKey)
	alice, received := openSharedClient(t, ctx, address, public)
	if _, err := alice.SetName(ctx, "Alice"); err != nil {
		t.Fatal(err)
	}
	var rooms []community.Genesis
	var configs []node.RoomConfig
	for _, name := range []string{"A", "B"} {
		roomKey := clientTestPrivateKey(t)
		g, err := community.NewGenesis(roomKey, nodeKey, time.Now(), name, "", true, [][]byte{alice.key.Public().(ed25519.PublicKey)})
		if err != nil {
			t.Fatal(err)
		}
		selected, err := root.ForRoom(g.RoomKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := selected.Initialize(ctx, g, roomKey); err != nil {
			t.Fatal(err)
		}
		rooms = append(rooms, g)
		configs = append(configs, node.RoomConfig{Genesis: &rooms[len(rooms)-1], RoomKey: roomKey})
	}
	n, err := node.New(node.Config{Key: nodeKey, Listen: address, Socket: filepath.Join(t.TempDir(), "node.sock"), Store: root, LocalOnly: true, Rooms: configs, DM: testDMConfig()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	bob, bobEvents := openSharedClient(t, ctx, address, public)
	joinSharedRooms(t, ctx, alice, rooms)
	joinSharedRooms(t, ctx, bob, rooms)
	old := waitSharedConnection(t, ctx, alice, rooms, nil)
	for _, g := range rooms {
		if _, err := bob.SendMessage(ctx, keyText(g.RoomKey), g.Name); err != nil {
			t.Fatal(err)
		}
		expectSharedEvent(t, ctx, alice, received, g.RoomKey, g.Name)
		expectSharedEvent(t, ctx, bob, bobEvents, g.RoomKey, g.Name)
		record, err := alice.store.room(ctx, g.RoomKey)
		if err != nil || record.HeadSeqno != 1 {
			t.Fatalf("room counters mixed: %+v %v", record, err)
		}
	}
	// One physical failure wakes both leases; their workers converge on a single
	// new connection instead of repeatedly replacing each other's socket.
	staleA := sharedSession(alice, rooms[0].RoomKey)
	old.Close()
	fresh := waitSharedConnection(t, ctx, alice, rooms, old)
	staleA.Close()
	for _, g := range rooms {
		if _, err := alice.SendMessage(ctx, keyText(g.RoomKey), "after loss"); err != nil {
			t.Fatal(err)
		}
		expectSharedEvent(t, ctx, alice, received, g.RoomKey, "after loss")
		expectSharedEvent(t, ctx, bob, bobEvents, g.RoomKey, "after loss")
		if sharedSession(alice, g.RoomKey).Peer != fresh {
			t.Fatal("room connection churn after recovery")
		}
	}
	left := sharedSession(alice, rooms[0].RoomKey)
	if err := alice.Leave(ctx, keyText(rooms[0].RoomKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.store.room(ctx, rooms[0].RoomKey); err == nil {
		t.Fatal("leave kept room cache")
	}
	left.Close()
	if _, err := bob.SendMessage(ctx, keyText(rooms[0].RoomKey), "left room"); err != nil {
		t.Fatal(err)
	}
	expectSharedEvent(t, ctx, bob, bobEvents, rooms[0].RoomKey, "left room")
	if _, err := bob.SendMessage(ctx, keyText(rooms[1].RoomKey), "B remains"); err != nil {
		t.Fatal(err)
	}
	expectSharedEvent(t, ctx, bob, bobEvents, rooms[1].RoomKey, "B remains")
	expectSharedEvent(t, ctx, alice, received, rooms[1].RoomKey, "B remains")
	if sharedSession(alice, rooms[1].RoomKey).Peer != fresh {
		t.Fatal("leave replaced B's connection")
	}
	// Rejoin A, then rotate identity with both rooms connected.
	joinSharedRooms(t, ctx, alice, rooms[:1])
	for _, text := range []string{"A", "after loss", "left room"} {
		expectSharedEvent(t, ctx, alice, received, rooms[0].RoomKey, text)
	}
	beforeA, beforeB := sharedSession(alice, rooms[0].RoomKey), sharedSession(alice, rooms[1].RoomKey)
	oldOwner := alice.connector
	identity := alice.Identity()
	if _, err := alice.ResetIdentity(ctx, identity.Key); err != nil {
		t.Fatal(err)
	}
	if alice.connector == oldOwner || alice.Identity().Key == identity.Key || alice.Identity().Name != "Alice" {
		t.Fatal("identity reset retained the old owner")
	}
	for _, s := range []*replica.Session{beforeA, beforeB} {
		select {
		case <-s.Done:
		default:
			t.Fatal("reset left an old lease live")
		}
	}
	afterReset := waitSharedConnection(t, ctx, alice, rooms, fresh)
	beforeA.Close()
	beforeB.Close()
	_, err = alice.SubmitMutation(ctx, keyText(rooms[1].RoomKey), community.EventMetadata{Name: "must reject"})
	var rejected *RejectedError
	if !errors.As(err, &rejected) || rejected.Code != community.RejectPermissionDenied {
		t.Fatalf("new identity inherited admin authority: %v", err)
	}
	if _, err := alice.SendMessage(ctx, keyText(rooms[1].RoomKey), "new identity"); err != nil {
		t.Fatal(err)
	}
	expectSharedEvent(t, ctx, alice, received, rooms[1].RoomKey, "new identity")
	history, _, err := alice.store.timeline(ctx, rooms[1].RoomKey, 0, 100)
	if err != nil || !bytes.Equal(history[len(history)-1].Proposal.AuthorKey, alice.key.Public().(ed25519.PublicKey)) {
		t.Fatalf("submission carried the old identity: %v", err)
	}
	if sharedSession(alice, rooms[1].RoomKey).Peer != afterReset {
		t.Fatal("stale close killed new identity")
	}
	// DM delivery is independent of the remaining room connection.
	// The preceding scripted room burst exhausts the leaf's configured query
	// budget. Exercise the DM cutover on a fresh, shared authenticated session.
	oldBob := sharedSession(bob, rooms[1].RoomKey).Peer
	_ = oldBob.Close()
	waitSharedConnection(t, ctx, bob, rooms, oldBob)
	alice.identityOps.Lock()
	_, dmErr := alice.ensureDM()
	alice.identityOps.Unlock()
	if dmErr != nil {
		t.Fatal(dmErr)
	}
	if _, err := bob.SendDM(ctx, alice.Identity().Key, "independent B"); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-received:
		v := n.Params.(map[string]any)
		if n.Method != "dm.message" || v["room"] != nil || v["text"] != "independent B" {
			t.Fatalf("misrouted DM: %#v", n)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-afterReset.Done():
	default:
		t.Fatal("client shutdown retained its connection")
	}
}

// A hostile two-room endpoint permits invalid signed wire data to exercise the
// shared dispatcher without adding injection hooks to the production node.
func TestSharedDispatcherRejectsWrongRoomAndInvalidData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nodeKey := clientTestPrivateKey(t)
	keys := []ed25519.PrivateKey{clientTestPrivateKey(t), clientTestPrivateKey(t)}
	rooms := make([]community.Genesis, 2)
	states := make([]community.RoomStateV3, 2)
	ids := make([][]byte, 2)
	for i := range rooms {
		var err error
		rooms[i], err = community.NewGenesis(keys[i], nodeKey, time.Now(), fmt.Sprint(i), "", true, nil)
		if err != nil {
			t.Fatal(err)
		}
		projection, _ := community.NewProjection(rooms[i])
		states[i], err = community.SignRoomStateV3(keys[i], projection.State())
		if err != nil {
			t.Fatal(err)
		}
		ids[i], _ = community.OverlayID(rooms[i].RoomKey)
	}
	server, err := roomnet.NewGateway(nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	peers := make(chan *roomnet.Peer, 8)
	var probes atomic.Int32
	server.SetConnectionHandler(func(raw *quic.Peer) error {
		peer := roomnet.Wrap(raw)
		peers <- peer
		peer.SetQueryHandler(func(q *roomnet.Query) error {
			if _, ok := q.Data.(community.GetCapabilities); ok {
				probes.Add(1)
				return q.Answer(roomnet.LocalCapabilities())
			}
			if _, ok := q.Data.(broadcast.GetTime); ok {
				return q.Answer(broadcast.Time{Now: int32(time.Now().Unix())})
			}
			wrapper, ok := q.Data.(community.OverlayQueryV1)
			if !ok {
				return roomnet.ErrNoAnswer
			}
			for i, id := range ids {
				if !bytes.Equal(wrapper.Overlay, id) {
					continue
				}
				if selected, err := q.SelectOverlay(id); err != nil || !selected {
					return err
				}
				switch q.Data.(type) {
				case community.GetRoomGenesis:
					return q.Answer(rooms[i])
				case community.GetEvents:
					return q.Answer(community.EventList{})
				case community.GetRoomState:
					return q.Answer(community.RoomStateResult{State: states[i], Stats: community.RoomStats{Ready: true}})
				}
			}
			return roomnet.ErrNoAnswer
		})
		return nil
	})
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close(); packet.Close() })
	go server.Serve(packet)
	c, events := openSharedClient(t, ctx, packet.LocalAddr().String(), nodeKey.Public().(ed25519.PublicKey))
	joinSharedRooms(t, ctx, c, rooms)
	var remote *roomnet.Peer
	select {
	case remote = <-peers:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	shared := waitSharedConnection(t, ctx, c, rooms, nil)
	proposal, err := community.SignProposal(keys[1], rooms[1].NodeKey, community.EventProposal{RoomID: rooms[1].RoomKey, Nonce: community.Zero256(), Timestamp: time.Now().Unix(), Body: community.EventMessage{Text: "hostile"}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := community.SignCommit(keys[1], proposal, 1, community.Zero256(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	send := func(key ed25519.PrivateKey, event community.CommittedEvent, tamper bool) {
		t.Helper()
		data, err := community.Encode(event)
		if err != nil {
			t.Fatal(err)
		}
		wrapper, err := broadcast.Sign(key, nil, data, time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		if tamper {
			wrapper.Signature[0] ^= 1
		}
		if err := remote.SendMessage(ctx, wrapper); err != nil {
			t.Fatal(err)
		}
	}
	send(keys[0], event, false) // source A, inner room B
	send(keys[1], event, true)  // invalid outer signature
	// Invalid broadcasts must not affect either room or the shared transport.
	var clock broadcast.Time
	if err := shared.Query(ctx, broadcast.GetTime{}, &clock); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-events:
		t.Fatalf("invalid input notified: %#v", n)
	case <-time.After(30 * time.Millisecond):
	}
	for _, g := range rooms {
		record, err := c.store.room(ctx, g.RoomKey)
		if err != nil || record.HeadSeqno != 0 {
			t.Fatal("invalid input changed history", err)
		}
	}
	// Invalid canonical signature closes only B's lease; A and the physical
	// connection survive while B recovers using the same verified capabilities.
	oldB := sharedSession(c, rooms[1].RoomKey)
	event.Signature[0] ^= 1
	send(keys[1], event, false)
	select {
	case <-oldB.Done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if got := waitSharedConnection(t, ctx, c, rooms, nil); got != shared || probes.Load() != 1 {
		t.Fatal("invalid room data closed another room's connection")
	}
	select {
	case n := <-events:
		t.Fatalf("invalid commit notified: %#v", n)
	default:
	}
	// Default sequencer calibration uses this same owner, even from a relayed
	// room session; it must not create a temporary replacement connection.
	r, _ := c.connectedRoom(keyText(rooms[0].RoomKey))
	snapshot, _ := c.snapshotRoomIdentity(r)
	relayKey := clientTestPrivateKey(t)
	relayPeer := clockTestPeer(t, snapshot.key, relayKey, int32(time.Now().Unix()), nil)
	relaySession := &replica.Session{Genesis: rooms[0], Peer: relayPeer, Done: relayPeer.Done()}
	r.mu.Lock()
	actual := r.session
	r.session = relaySession
	r.mu.Unlock()
	snapshot.session = relaySession
	_, err = r.sequencerTimestamp(ctx, snapshot)
	r.mu.Lock()
	r.session = actual
	r.mu.Unlock()
	if err != nil || probes.Load() != 1 {
		t.Fatalf("calibration replaced live room connection: %v", err)
	}
	if err := shared.Query(ctx, broadcast.GetTime{}, &clock); err != nil {
		t.Fatal(err)
	}
}
