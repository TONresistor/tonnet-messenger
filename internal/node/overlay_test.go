package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/adnl/quic"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

func TestOverlayMembershipReadsSubmitBatchAndSync(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	room, nodeKey, identity := integrationKey(t), integrationKey(t), integrationKey(t)
	genesis, err := community.NewGenesis(room, nodeKey, time.Now(), "Wrapped", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Initialize(ctx, genesis, room); err != nil {
		t.Fatal(err)
	}
	listen := integrationAddress(t)
	runtime, err := New(Config{Key: nodeKey, Listen: listen, Socket: filepath.Join(t.TempDir(), "node.sock"), Genesis: &genesis, Store: db, RoomKey: room})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	gateway, err := roomnet.NewGateway(identity)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	raw, err := gateway.DialDefault(ctx, genesis.NodeKey, listen)
	if err != nil {
		t.Fatal(err)
	}
	peer := roomnet.Wrap(raw)
	id, _ := community.OverlayID(genesis.RoomKey)
	proposal, err := community.SignProposal(identity, genesis.NodeKey, community.EventProposal{RoomID: genesis.RoomKey, Nonce: community.Zero256(), Timestamp: time.Now().Unix(), Body: community.EventMessage{Text: "wrapped"}})
	if err != nil {
		t.Fatal(err)
	}
	inner, _ := community.Encode(community.SubmitEvent{Proposal: proposal})
	for _, request := range []community.OverlayQueryV1{{Overlay: community.Zero256(), Tier: 1, Query: inner}, {Overlay: id, Tier: 1, Query: inner}} {
		var rejected community.OverlayRejectedV1
		if err := peer.Query(ctx, request, &rejected); err != nil {
			t.Fatal(err)
		}
		want := community.RejectMalformedRequest
		if !bytes.Equal(request.Overlay, id) {
			want = community.RejectOverlayNotServed
		}
		if rejected.Code != want {
			t.Fatalf("rejection: %+v", rejected)
		}
	}
	for _, request := range []any{community.SubmitEvent{Proposal: proposal}, tonoverlay.GetRandomPeers{}} {
		var answer any
		if err := peer.Query(ctx, request, &answer); err == nil || !strings.Contains(err.Error(), "canceled by remote") {
			t.Fatalf("bare %T: %v", request, err)
		}
	}
	var remote broadcast.Time
	if err := peer.Query(ctx, broadcast.GetTime{}, &remote); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.GetRandomPeers(ctx, id); err != nil {
		t.Fatal(err)
	}
	if members, _ := runtime.peers.counts(); members != 0 {
		t.Fatalf("selection/time/discovery joined %d members", members)
	}
	head, err := db.Head(ctx)
	if err != nil || head.Seqno != 0 {
		t.Fatalf("rejected wrapper mutated history: %+v %v", head, err)
	}
	var gotGenesis community.Genesis
	if err := peer.QueryRoom(ctx, genesis.RoomKey, community.GetRoomGenesis{}, &gotGenesis); err != nil {
		t.Fatal(err)
	}
	if members, _ := runtime.peers.counts(); members != 1 {
		t.Fatalf("valid selection did not join: %d", members)
	}
	var accepted community.SubmitAccepted
	if err := peer.QueryRoom(ctx, genesis.RoomKey, community.SubmitEvent{Proposal: proposal}, &accepted); err != nil || accepted.Event.Seqno != 1 {
		t.Fatalf("submit: %+v %v", accepted, err)
	}
	queries := []any{community.GetRoomGenesis{}, community.GetRoomState{}, community.GetEvents{}, community.GetMessagesRecent{}, community.GetMessagesBefore{MessageID: 2}}
	batch := community.Batch{}
	for _, request := range queries {
		raw, err := community.Encode(request)
		if err != nil {
			t.Fatal(err)
		}
		batch.Queries = append(batch.Queries, raw)
	}
	// A wrapped subquery remains unsupported; only the outer batch is wrapped.
	wrapped, _ := community.Encode(community.OverlayQueryV1{Overlay: id, Query: batch.Queries[0]})
	batch.Queries = append(batch.Queries, wrapped)
	var result community.BatchResult
	if err := peer.QueryRoom(ctx, genesis.RoomKey, batch, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 6 {
		t.Fatalf("batch: %+v", result)
	}
	for i, item := range result.Items {
		if i == 5 {
			if item.Code != community.RejectUnsupportedEvent {
				t.Fatalf("wrapped subquery: %+v", item)
			}
			continue
		}
		if item.Code != 0 {
			t.Fatalf("batch item %d: %+v", i, item)
		}
		if _, err := community.DecodeAny(item.Data); err != nil {
			t.Fatal(err)
		}
	}
	if events, err := community.DecodeAny(result.Items[2].Data); err != nil || len(events.(community.EventList).Events) != 1 {
		t.Fatalf("batch history: %v %v", events, err)
	}
	replicaDB, err := store.Open(ctx, filepath.Join(t.TempDir(), "replica.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer replicaDB.Close()
	if err := replicaDB.InitializeReplica(ctx, genesis); err != nil {
		t.Fatal(err)
	}
	if _, err := replica.Sync(ctx, replica.Config{RoomID: genesis.RoomKey, NodeKey: integrationKey(t), DirectAddress: listen, DirectPublic: genesis.NodeKey}, replicaDB); err != nil {
		t.Fatal(err)
	}
	if err := replicaDB.ReplicaReady(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestForwardedOverlayRejectionsAndSuccessfulSubmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	room, sequencer, relayKey, identity := integrationKey(t), integrationKey(t), integrationKey(t), integrationKey(t)
	genesis, err := community.NewGenesis(room, sequencer, time.Now(), "Forward", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := store.Open(ctx, filepath.Join(t.TempDir(), "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if err := authority.Initialize(ctx, genesis, room); err != nil {
		t.Fatal(err)
	}
	destination, err := store.Open(ctx, filepath.Join(t.TempDir(), "replica.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	if err := destination.InitializeReplica(ctx, genesis); err != nil {
		t.Fatal(err)
	}
	state, err := authority.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := destination.InstallReplicaState(ctx, state); err != nil {
		t.Fatal(err)
	}
	server, err := roomnet.NewGateway(sequencer)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var rejection atomic.Int32
	seen := make(chan community.EventProposal, 3)
	id, _ := community.OverlayID(genesis.RoomKey)
	server.SetConnectionHandler(func(raw *quic.Peer) error {
		peer := roomnet.Wrap(raw)
		peer.SetQueryHandler(func(q *roomnet.Query) error {
			if selected, err := q.SelectOverlay(id); err != nil || !selected {
				return err
			}
			switch request := q.Data.(type) {
			case tonoverlay.GetRandomPeers:
				return q.Answer(tonoverlay.NodesList{})
			case community.SubmitEvent:
				seen <- request.Proposal
				if code := rejection.Load(); code != 0 {
					return q.Answer(community.OverlayRejectedV1{Code: code, Message: "upstream wrapper"})
				}
				result, err := authority.Commit(ctx, request.Proposal, room, time.Now())
				if err != nil {
					return err
				}
				return q.Answer(community.SubmitAccepted{Event: result.Event})
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
	defer packet.Close()
	go func() { _ = server.Serve(packet) }()
	listen := integrationAddress(t)
	runtime, err := New(Config{Key: relayKey, Listen: listen, Genesis: &genesis, Store: destination, NodeRole: community.NodeRoleRelay})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	sequencerID, _ := community.KeyID(genesis.NodeKey)
	peerID := hex.EncodeToString(sequencerID)
	runtime.peers.markKnown(peerID)
	if _, err := runtime.qgw.DialDefault(ctx, genesis.NodeKey, packet.LocalAddr().String()); err != nil {
		t.Fatal(err)
	}
	upstream, ok := runtime.peers.get(peerID)
	if !ok {
		t.Fatal("upstream not registered")
	}
	if _, ok := runtime.probeNode(ctx, upstream); !ok {
		t.Fatal("wrapped peer probe failed")
	}
	session, err := replica.DialRoom(ctx, replica.Config{RoomID: genesis.RoomKey, NodeKey: identity, DirectAddress: listen, DirectPublic: relayKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	proposal, err := community.SignProposal(identity, genesis.NodeKey, community.EventProposal{RoomID: genesis.RoomKey, Nonce: community.Zero256(), Timestamp: time.Now().Unix(), Body: community.EventMessage{Text: "forward exact bytes"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []int32{19, 1, 0} {
		rejection.Store(code)
		var answer any
		err := session.Peer.QueryRoom(ctx, genesis.RoomKey, community.SubmitEvent{Proposal: proposal}, &answer)
		if code != 0 {
			var rejected *roomnet.OverlayRejection
			if !errors.As(err, &rejected) || rejected.Code != code {
				t.Fatalf("forwarded code %d: %v", code, err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		got := <-seen
		wantRaw, _ := community.Encode(proposal)
		gotRaw, _ := community.Encode(got)
		if !bytes.Equal(wantRaw, gotRaw) {
			t.Fatal("forwarder changed signed proposal")
		}
	}
	head, err := destination.Head(ctx)
	if err != nil || head.Seqno != 1 {
		t.Fatalf("forwarded history: %+v %v", head, err)
	}
	if err := destination.Audit(ctx); err != nil {
		t.Fatal(err)
	}
}
