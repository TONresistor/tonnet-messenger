package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

func fixtureRoom(t *testing.T, cfg Config) *roomContext {
	t.Helper()
	if cfg.Socket == "" {
		cfg.Socket = filepath.Join(t.TempDir(), "unused.sock")
	}
	room, err := newRoomContext(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return room
}

type roomBindingRecord struct {
	key     ed25519.PrivateKey
	genesis community.Genesis
	view    *store.Store
}
type roomBindingFixture struct {
	root  *store.Store
	path  string
	node  ed25519.PrivateKey
	rooms [2]roomBindingRecord
}

func sharedRoomBinding(t *testing.T) *roomBindingFixture {
	t.Helper()
	f := &roomBindingFixture{path: filepath.Join(t.TempDir(), "shared.db"), node: integrationKey(t)}
	var err error
	f.root, err = store.Open(context.Background(), f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.root.Close() })
	for i := range f.rooms {
		r := &f.rooms[i]
		r.key = integrationKey(t)
		r.genesis, err = community.NewGenesis(r.key, f.node, time.Now(), fmt.Sprintf("Room %d", i), "", true, [][]byte{integrationKey(t).Public().(ed25519.PublicKey)})
		if err != nil {
			t.Fatal(err)
		}
		r.view, err = f.root.ForRoom(r.genesis.RoomKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.view.Initialize(context.Background(), r.genesis, r.key); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func bindingRawState(t *testing.T, f *roomBindingFixture, index int) []byte {
	t.Helper()
	db, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw []byte
	if err := db.QueryRow("SELECT raw_signed_state FROM room_state WHERE room_id=?", f.rooms[index].genesis.RoomKey).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func bindingLegacyState(t *testing.T, f *roomBindingFixture, index int) community.RoomStateV3 {
	t.Helper()
	r := &f.rooms[index]
	state, err := r.view.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := community.SignRoomState(r.key, community.RoomState{RoomID: state.RoomID, RevisionSeqno: state.RevisionSeqno, RevisionHash: state.RevisionHash, Name: state.Name, Description: state.Description, WritePolicy: state.WritePolicy, Admins: state.Admins, Moderators: state.Moderators, PinnedMessages: state.PinnedMessages})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := community.Encode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE room_state SET raw_signed_state=? WHERE room_id=?", raw, r.genesis.RoomKey); err != nil {
		t.Fatal(err)
	}
	return state
}

func bindingConfig(t *testing.T, f *roomBindingFixture, index int) Config {
	t.Helper()
	return Config{Key: f.node, Listen: integrationAddress(t), Socket: filepath.Join(t.TempDir(), "node.sock"), Genesis: &f.rooms[index].genesis, Store: f.root, RoomKey: f.rooms[index].key}
}

func TestNodeRoomContextSelectsFromSharedStore(t *testing.T) {
	for _, legacySibling := range []bool{true, false} {
		t.Run(fmt.Sprint("legacySibling=", legacySibling), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			f := sharedRoomBinding(t)
			a, b := &f.rooms[0], &f.rooms[1]
			body := any(community.EventMessage{Text: "sibling history"})
			if !legacySibling {
				body = community.EventBanV1{SubjectKey: integrationKey(t).Public().(ed25519.PublicKey)}
			}
			proposal, err := community.SignProposal(b.key, b.genesis.NodeKey, community.EventProposal{RoomID: b.genesis.RoomKey, Nonce: community.Zero256(), Timestamp: time.Now().Unix(), Body: body})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.view.Commit(ctx, proposal, b.key, time.Now()); err != nil {
				t.Fatal(err)
			}
			want := bindingLegacyState(t, f, 0)
			if legacySibling {
				bindingLegacyState(t, f, 1)
			}
			before := bindingRawState(t, f, 1)
			beforeHead, err := b.view.Head(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := f.root.Genesis(ctx); !errors.Is(err, store.ErrAmbiguousRoom) {
				t.Fatalf("fixture root is not ambiguous: %v", err)
			}
			cfg := bindingConfig(t, f, 0)
			n, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			if n.room.store == f.root || n.cfg.Store != nil || n.cfg.Genesis != nil || len(n.cfg.RoomKey) != 0 || len(n.cfg.OverlayID) != 0 {
				t.Fatal("room binding/authority remained on the transport configuration")
			}
			if n.database != f.root {
				t.Fatal("database maintenance lost the shared database")
			}
			state, err := a.view.State(ctx)
			if err != nil || state.Verify() != nil || state.RevisionSeqno != want.RevisionSeqno || !bytes.Equal(state.RevisionHash, want.RevisionHash) {
				t.Fatalf("selected V2 was not converted at its revision: %+v %v", state, err)
			}
			identity := integrationKey(t)
			session, err := replica.DialSequencer(ctx, replica.Config{RoomID: a.genesis.RoomKey, NodeKey: identity, DirectAddress: cfg.Listen, DirectPublic: f.node.Public().(ed25519.PublicKey)})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			var current community.RoomStateResult
			if err := session.Peer.QueryRoom(ctx, a.genesis.RoomKey, community.GetRoomState{}, &current); err != nil || current.State.Name != a.genesis.Name || !current.Stats.Ready {
				t.Fatalf("selected room read: %+v %v", current, err)
			}
			message, err := community.SignProposal(identity, a.genesis.NodeKey, community.EventProposal{RoomID: a.genesis.RoomKey, Nonce: community.Zero256(), Timestamp: time.Now().Unix(), Body: community.EventMessage{Text: "selected room"}})
			if err != nil {
				t.Fatal(err)
			}
			var accepted community.SubmitAccepted
			if err := session.Peer.QueryRoom(ctx, a.genesis.RoomKey, community.SubmitEvent{Proposal: message}, &accepted); err != nil || accepted.Event.Seqno != 1 {
				t.Fatalf("selected room write: %+v %v", accepted, err)
			}
			message.RoomID = b.genesis.RoomKey
			message.Nonce[0] = 1
			message, err = community.SignProposal(identity, a.genesis.NodeKey, message)
			if err != nil {
				t.Fatal(err)
			}
			var rejected community.SubmitRejected
			if err := session.Peer.QueryRoom(ctx, a.genesis.RoomKey, community.SubmitEvent{Proposal: message}, &rejected); err != nil || rejected.Code != community.RejectWrongRoom {
				t.Fatalf("sibling proposal accepted: %+v %v", rejected, err)
			}
			var unavailable any
			err = session.Peer.QueryRoom(ctx, b.genesis.RoomKey, community.GetRoomState{}, &unavailable)
			var overlay *roomnet.OverlayRejection
			if !errors.As(err, &overlay) || overlay.Code != community.RejectOverlayNotServed {
				t.Fatalf("second network room was activated: %v", err)
			}
			status := n.Status()
			id, _ := community.RoomKeyText(a.genesis.RoomKey)
			if len(status.Rooms) != 1 || status.Rooms[0].RoomID != id || status.Rooms[0].Seqno != 1 || status.Rooms[0].NodeRole != community.NodeRoleSequencer {
				t.Fatalf("room status: %+v", status.Rooms)
			}
			afterHead, err := b.view.Head(ctx)
			if err != nil || afterHead.Seqno != beforeHead.Seqno || !bytes.Equal(afterHead.Hash, beforeHead.Hash) || !bytes.Equal(bindingRawState(t, f, 1), before) {
				t.Fatalf("startup/operations changed sibling: %v", err)
			}
			if _, _, err := f.root.Genesis(ctx); !errors.Is(err, store.ErrAmbiguousRoom) {
				t.Fatal("node modified root selection")
			}
		})
	}
}

func TestNodeRoomContextRejectsAuthorityBeforeConversion(t *testing.T) {
	for _, mode := range []string{"absent sequencer", "absent replica", "wrong room key", "wrong node key", "replica authority", "mismatched genesis", "invalid role", "missing socket", "short node key"} {
		t.Run(mode, func(t *testing.T) {
			f := sharedRoomBinding(t)
			bindingLegacyState(t, f, 0)
			bindingLegacyState(t, f, 1)
			beforeA, beforeB := bindingRawState(t, f, 0), bindingRawState(t, f, 1)
			cfg := bindingConfig(t, f, 0)
			var want error
			switch mode {
			case "absent sequencer", "absent replica":
				private := integrationKey(t)
				g, err := community.NewGenesis(private, f.node, time.Now(), "Absent", "", true, nil)
				if err != nil {
					t.Fatal(err)
				}
				cfg.Genesis = &g
				cfg.RoomKey = private
				want = store.ErrNotInitialized
				if mode == "absent replica" {
					cfg.NodeRole = community.NodeRoleRelay
					cfg.RoomKey = nil
					cfg.Key = integrationKey(t)
				}
			case "wrong room key":
				cfg.RoomKey = f.rooms[1].key
			case "wrong node key":
				cfg.Key = integrationKey(t)
			case "replica authority":
				cfg.NodeRole = community.NodeRoleRelay
				cfg.Key = integrationKey(t)
			case "mismatched genesis":
				g, err := community.NewGenesis(f.rooms[0].key, f.node, time.Now(), "Other genesis", "", true, nil)
				if err != nil {
					t.Fatal(err)
				}
				cfg.Genesis = &g
				want = store.ErrGenesisMismatch
			case "invalid role":
				cfg.NodeRole = 99
			case "missing socket":
				cfg.Socket = ""
			case "short node key":
				cfg.Key = ed25519.PrivateKey{1}
			}
			n, err := New(cfg)
			if err == nil {
				n.Close()
				t.Fatal("invalid authority/selection accepted")
			}
			if want != nil && !errors.Is(err, want) {
				t.Fatalf("wrong rejection: %v", err)
			}
			if !bytes.Equal(beforeA, bindingRawState(t, f, 0)) || !bytes.Equal(beforeB, bindingRawState(t, f, 1)) {
				t.Fatal("rejected startup converted stored state")
			}
		})
	}
}

func TestReplicaRoomContextRequiresVerifiedV3AndNeverConverts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := sharedRoomBinding(t)
	state := bindingLegacyState(t, f, 0)
	bindingLegacyState(t, f, 1)
	beforeA, beforeB := bindingRawState(t, f, 0), bindingRawState(t, f, 1)
	cfg := bindingConfig(t, f, 0)
	cfg.NodeRole = community.NodeRoleRelay
	cfg.RoomKey = nil
	cfg.Key = integrationKey(t)
	cfg.Socket = ""
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if len(n.room.roomKey) != 0 || n.room.role != community.NodeRoleRelay || !bytes.Equal(beforeA, bindingRawState(t, f, 0)) || n.Status().Rooms[0].Ready {
		t.Fatal("replica converted/signed legacy state or became ready")
	}
	invalid := state
	invalid.Signature = bytes.Clone(state.Signature)
	invalid.Signature[0] ^= 1
	if err := n.room.store.InstallReplicaState(ctx, invalid); err == nil || n.Status().Rooms[0].Ready {
		t.Fatal("invalid state made replica ready")
	}
	if err := n.room.store.InstallReplicaState(ctx, state); err != nil {
		t.Fatal(err)
	}
	if !n.Status().Rooms[0].Ready {
		t.Fatal("verified V3 did not make selected replica ready")
	}
	want, _ := community.Encode(state)
	if !bytes.Equal(want, bindingRawState(t, f, 0)) || !bytes.Equal(beforeB, bindingRawState(t, f, 1)) {
		t.Fatal("replica changed sequencer signature or sibling")
	}
	session, err := replica.DialRoom(ctx, replica.Config{RoomID: f.rooms[0].genesis.RoomKey, NodeKey: integrationKey(t), DirectAddress: cfg.Listen, DirectPublic: cfg.Key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var result community.RoomStateResult
	if err := session.Peer.QueryRoom(ctx, f.rooms[0].genesis.RoomKey, community.GetRoomState{}, &result); err != nil || !result.Stats.Ready || result.Stats.NodeRole != community.NodeRoleRelay || result.State.Verify() != nil {
		t.Fatalf("replica current state: %+v %v", result, err)
	}
}

func TestRoomContextOwnsItsInputAndBorrowsDatabase(t *testing.T) {
	f := sharedRoomBinding(t)
	input := cloneRoomGenesis(f.rooms[0].genesis)
	cfg := bindingConfig(t, f, 0)
	cfg.Genesis = &input
	cfg.RoomKey = bytes.Clone(cfg.RoomKey)
	cfg.Key = bytes.Clone(cfg.Key)
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wantOverlay, _ := community.OverlayID(f.rooms[0].genesis.RoomKey)
	input.Name = "mutated"
	input.RoomKey[0] ^= 1
	input.NodeKey[0] ^= 1
	input.Signature[0] ^= 1
	input.InitialAdmins[0][0] ^= 1
	cfg.RoomKey[0] ^= 1
	cfg.Key[0] ^= 1
	if n.room.genesis.VerifyNow() != nil || n.room.genesis.Name != f.rooms[0].genesis.Name || !bytes.Equal(n.room.roomKey, f.rooms[0].key) || !bytes.Equal(n.room.overlayID, wantOverlay) || !bytes.Equal(n.cfg.Key, f.node) {
		t.Fatal("caller retained mutable ownership of runtime authority")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.rooms[1].view.Head(context.Background()); err != nil {
		t.Fatalf("closing node closed the caller's database: %v", err)
	}
}
