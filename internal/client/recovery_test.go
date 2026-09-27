package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/xssnick/tonutils-go/adnl/quic"
)

func TestClientReopenPreservesVerifiedHistory(t *testing.T) {
	for _, mode := range []string{"message_only", "metadata_refresh_failed", "metadata_state_current", "initial_state_missing", "state_malformed"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			instance, err := Open(ctx, Config{StateDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if instance != nil {
					instance.Close()
				}
			})
			room, node := clientTestPrivateKey(t), clientTestPrivateKey(t)
			genesis, err := community.NewGenesis(room, node, time.Now(), "Room", "", true, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := instance.store.addRoom(ctx, genesis.RoomKey, "room", nil); err != nil {
				t.Fatal(err)
			}
			if err := instance.store.pinGenesis(ctx, genesis.RoomKey, genesis); err != nil {
				t.Fatal(err)
			}
			projection, err := community.NewProjection(genesis)
			if err != nil {
				t.Fatal(err)
			}
			state, err := community.SignRoomState(room, projection.State())
			if err != nil {
				t.Fatal(err)
			}
			if mode != "initial_state_missing" {
				if err := instance.store.installRoom(ctx, genesis.RoomKey, genesis, projection, state); err != nil {
					t.Fatal(err)
				}
			}
			session := &replica.Session{Genesis: genesis}
			handle := &roomHandle{client: instance, key: genesis.RoomKey, ctx: ctx, session: session, sessionEpoch: 1}
			sign := func(seq int64, previous []byte, body any) community.CommittedEvent {
				nonce := make([]byte, 32)
				nonce[0] = byte(seq)
				p, e := community.SignProposal(room, genesis.NodeKey, community.EventProposal{RoomID: genesis.RoomKey, Nonce: nonce, Timestamp: time.Now().Unix(), Body: body})
				if e != nil {
					t.Fatal(e)
				}
				c, e := community.SignCommit(room, p, seq, previous, time.Now())
				if e != nil {
					t.Fatal(e)
				}
				return c
			}
			message := sign(1, community.Zero256(), community.EventMessage{Text: "keep this message"})
			if durable, e := handle.processCanonical(ctx, session, 1, message); e != nil || !durable {
				t.Fatalf("message durable=%v err=%v", durable, e)
			}
			count := 1
			if mode == "metadata_refresh_failed" || mode == "metadata_state_current" {
				hash, e := message.Hash()
				if e != nil {
					t.Fatal(e)
				}
				metadata := sign(2, hash, community.EventMetadata{Name: "Renamed"})
				durable, e := handle.processCanonical(ctx, session, 1, metadata)
				if !durable || e == nil {
					t.Fatalf("expected durable event followed by failed state query; durable=%v err=%v", durable, e)
				}

				count = 2
				if mode == "metadata_state_current" {
					state, e = community.SignRoomState(room, handle.projection.State())
					if e != nil {
						t.Fatal(e)
					}
					if e = instance.store.updateState(ctx, genesis.RoomKey, genesis, handle.projection, state); e != nil {
						t.Fatal(e)
					}
				}
			}
			if mode == "state_malformed" {
				if _, e := instance.store.db.ExecContext(ctx, "UPDATE joined_rooms SET raw_state=? WHERE room_key=?", []byte{1, 2, 3}, genesis.RoomKey); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := instance.store.projectRoom(ctx, genesis.RoomKey, genesis); e != nil {
				t.Fatalf("history invalid before restart: %v", e)
			}
			before, _, e := instance.store.timeline(ctx, genesis.RoomKey, 0, 10)
			if e != nil {
				t.Fatal(e)
			}
			key := append([]byte(nil), instance.key...)
			if e := instance.Close(); e != nil {
				t.Fatal(e)
			}
			instance, err = Open(ctx, Config{StateDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			events, _, e := instance.store.timeline(ctx, genesis.RoomKey, 0, 10)
			if e != nil {
				t.Fatal(e)
			}
			if len(events) != count || !reflect.DeepEqual(before, events) {
				t.Fatalf("verified history changed after reopen: got %d events, want %d", len(events), count)
			}
			record, e := instance.store.room(ctx, genesis.RoomKey)
			if e != nil {
				t.Fatal(e)
			}
			headHash, e := events[len(events)-1].Hash()
			if e != nil {
				t.Fatal(e)
			}
			if record.HeadSeqno != int64(count) || !bytes.Equal(record.HeadHash, headHash) || !reflect.DeepEqual(record.Genesis, genesis) || !bytes.Equal(instance.key, key) {
				t.Fatal("reopen changed the chain head, pinned genesis or identity")
			}
			projection, e = instance.store.projectRoom(ctx, genesis.RoomKey, genesis)
			if e != nil {
				t.Fatal(e)
			}
			state, e = community.SignRoomState(room, projection.State())
			if e != nil {
				t.Fatal(e)
			}
			if e = instance.store.installRoom(ctx, genesis.RoomKey, genesis, projection, state); e != nil {
				t.Fatalf("could not recover signed state: %v", e)
			}
		})
	}
}

func TestRecoveryErrorsPreserveStoredHistory(t *testing.T) {
	for _, corruption := range []string{"event", "head", "genesis"} {
		t.Run(corruption, func(t *testing.T) {
			f := newCanonicalIngestFixture(t)
			event := f.event(t, 1, community.Zero256(), community.EventMessage{Text: "keep"})
			if _, err := f.store.appendEvent(f.ctx, f.genesis.RoomKey, event); err != nil {
				t.Fatal(err)
			}
			query := "UPDATE room_events SET raw_event=x'010203' WHERE room_key=?"
			switch corruption {
			case "head":
				query = "UPDATE joined_rooms SET head_hash=zeroblob(32) WHERE room_key=?"
			case "genesis":
				query = "UPDATE joined_rooms SET raw_genesis=NULL WHERE room_key=?"
			}
			if _, err := f.store.db.ExecContext(f.ctx, query, f.genesis.RoomKey); err != nil {
				t.Fatal(err)
			}
			type snapshot struct {
				head                        int64
				hash, genesis, state, event []byte
			}
			read := func() snapshot {
				var result snapshot
				err := f.store.db.QueryRowContext(f.ctx, `SELECT head_seqno,head_hash,raw_genesis,raw_state,raw_event
FROM joined_rooms JOIN room_events USING(room_key) WHERE room_key=?`, f.genesis.RoomKey).
					Scan(&result.head, &result.hash, &result.genesis, &result.state, &result.event)
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			before := read()
			if err := f.store.validateOrRepairRooms(f.ctx); err == nil {
				t.Fatal("startup accepted corrupt history")
			}
			if !reflect.DeepEqual(before, read()) {
				t.Fatal("startup modified corrupt history")
			}
			if corruption != "genesis" {
				if err := f.handle.syncSessionLocked(f.ctx, f.session, 0); err == nil {
					t.Fatal("reconnection accepted corrupt history")
				}
				if !reflect.DeepEqual(before, read()) {
					t.Fatal("reconnection modified corrupt history")
				}
			}
		})
	}
}

func TestReconnectRecoversStateWithoutRewindingHistory(t *testing.T) {
	f := newCanonicalIngestFixture(t)
	event := f.event(t, 1, community.Zero256(), community.EventMetadata{Name: "Updated"})
	if _, err := f.store.appendEvent(f.ctx, f.genesis.RoomKey, event); err != nil {
		t.Fatal(err)
	}
	projection, err := f.store.projectRoom(f.ctx, f.genesis.RoomKey, f.genesis)
	if err != nil {
		t.Fatal(err)
	}
	state, err := community.SignRoomState(f.room, projection.State())
	if err != nil {
		t.Fatal(err)
	}
	conflict := projection.State()
	conflict.Name = "Conflicting"
	conflict, err = community.SignRoomState(f.room, conflict)
	if err != nil {
		t.Fatal(err)
	}
	var mode atomic.Int32
	cursors := make(chan int64, 3)
	serverKey := clientTestPrivateKey(t)
	server, err := roomnet.NewGateway(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.SetConnectionHandler(func(raw *quic.Peer) error {
		peer := roomnet.Wrap(raw)
		peer.SetQueryHandler(func(query *roomnet.Query) error {
			switch request := query.Data.(type) {
			case community.GetEvents:
				cursors <- request.AfterSeqno
				return query.Answer(community.EventList{})
			case community.GetRoomState:
				result := community.RoomStateResult{State: state, Stats: community.RoomStats{Ready: true, ReplicaSeqno: 1}}
				switch mode.Load() {
				case 0:
					result.Stats.ReplicaSeqno = 0
				case 1:
					result.State = conflict
				}
				return query.Answer(result)
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
	gateway, err := roomnet.NewGateway(clientTestPrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	raw, err := gateway.DialDefault(ctx, serverKey.Public().(ed25519.PublicKey), packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := roomnet.Wrap(raw)
	session := &replica.Session{Genesis: f.genesis, Peer: peer, Done: peer.Done()}
	f.handle.session = session
	for attempt := int32(0); attempt < 3; attempt++ {
		mode.Store(attempt)
		err := f.handle.syncSessionLocked(ctx, session, 0)
		if (attempt < 2 && err == nil) || (attempt == 2 && err != nil) {
			t.Fatalf("sync attempt %d: %v", attempt, err)
		}
		select {
		case cursor := <-cursors:
			if cursor != 1 {
				t.Fatalf("sync restarted from %d instead of the preserved head", cursor)
			}
		default:
			t.Fatal("sync did not request history")
		}
		if exists, err := f.store.hasEvent(ctx, f.genesis.RoomKey, event); err != nil || !exists {
			t.Fatalf("sync changed the stored event: exists=%v err=%v", exists, err)
		}
	}
	record, err := f.store.room(ctx, f.genesis.RoomKey)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := community.Encode(record.State)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := community.Encode(state)
	if err != nil {
		t.Fatal(err)
	}
	if record.HeadSeqno != 1 || !bytes.Equal(stored, expected) {
		t.Fatalf("signed state was not recovered: %v", err)
	}
}
