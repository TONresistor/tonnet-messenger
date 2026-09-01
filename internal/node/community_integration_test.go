package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"
	"time"

	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

func integrationKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestTONQUICRoutesDirectMessageBetweenOnlineIdentities(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	roomKey, nodeKey := integrationKey(t), integrationKey(t)
	alice, bob := integrationKey(t), integrationKey(t)
	genesis, err := community.NewGenesis(roomKey, nodeKey, time.Now(), "Room", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Initialize(ctx, genesis, roomKey); err != nil {
		t.Fatal(err)
	}
	listen := integrationAddress(t)
	runtime, err := New(Config{
		Key: nodeKey, Listen: listen, Socket: filepath.Join(t.TempDir(), "node.sock"),
		Genesis: &genesis, Store: database, RoomKey: roomKey, NodeRole: community.NodeRoleSequencer,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	dial := func(identity ed25519.PrivateKey) *replica.Session {
		t.Helper()
		session, err := replica.DialSequencer(ctx, replica.Config{
			RoomID: genesis.RoomKey, NodeKey: identity, DirectAddress: listen,
			DirectPublic: nodeKey.Public().(ed25519.PublicKey),
		})
		if err != nil {
			t.Fatal(err)
		}
		return session
	}
	aliceSession, bobSession := dial(alice), dial(bob)
	defer aliceSession.Close()
	defer bobSession.Close()

	received := make(chan any, 1)
	bobSession.Peer.SetMessageHandler(func(message any) error {
		received <- message
		return nil
	})
	now := time.Now()
	direct, err := community.SignDirectMessage(alice, community.DirectMessage{
		RoomID: genesis.RoomKey, ToKey: bob.Public().(ed25519.PublicKey),
		AuthorName: "alice", Timestamp: now.Unix(), Ciphertext: make([]byte, 28),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := community.Encode(direct)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := broadcast.Sign(alice, tonoverlay.CertificateEmpty{}, raw, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceSession.Peer.SendMessage(ctx, wrapper); err != nil {
		t.Fatal(err)
	}

	select {
	case message := <-received:
		got, ok := broadcast.AsBroadcast(message)
		if !ok {
			t.Fatalf("received %T, want signed broadcast", message)
		}
		delivered, err := community.DecodeDirectMessage(got.Data)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(delivered.FromKey, alice.Public().(ed25519.PublicKey)) ||
			!bytes.Equal(delivered.ToKey, bob.Public().(ed25519.PublicKey)) {
			t.Fatal("direct message identities changed in transit")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestTONQUICClientReadsFromVerifiedRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	roomKey, sequencerKey, relayKey := integrationKey(t), integrationKey(t), integrationKey(t)
	genesis, err := community.NewGenesis(roomKey, sequencerKey, time.Now(), "Room", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	authorityStore, err := store.Open(ctx, filepath.Join(t.TempDir(), "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer authorityStore.Close()
	if err := authorityStore.Initialize(ctx, genesis, roomKey); err != nil {
		t.Fatal(err)
	}
	state, err := authorityStore.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	relayStore, err := store.Open(ctx, filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer relayStore.Close()
	if err := relayStore.InitializeReplica(ctx, genesis); err != nil {
		t.Fatal(err)
	}
	if err := relayStore.InstallReplicaState(ctx, state); err != nil {
		t.Fatal(err)
	}

	listen := integrationAddress(t)
	runtime, err := New(Config{
		Key: relayKey, Listen: listen, Genesis: &genesis, Store: relayStore, NodeRole: community.NodeRoleRelay,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	config := replica.Config{
		RoomID: genesis.RoomKey, NodeKey: integrationKey(t), DirectAddress: listen,
		DirectPublic: relayKey.Public().(ed25519.PublicKey),
	}
	session, err := replica.DialRoom(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var result community.RoomStateResult
	if err := session.Peer.Query(ctx, community.GetRoomState{}, &result); err != nil {
		t.Fatal(err)
	}
	if result.Stats.NodeRole != community.NodeRoleRelay || !result.Stats.Ready {
		t.Fatalf("relay stats = %#v", result.Stats)
	}
	if sequencerSession, err := replica.DialSequencer(ctx, config); err == nil {
		sequencerSession.Close()
		t.Fatal("relay was accepted as authoritative sequencer")
	}
}

func integrationAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().String()
	listener.Close()
	return address
}

func TestIdentityQUICAuthorsProposalWithoutBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	roomKey, nodeKey, identityKey := integrationKey(t), integrationKey(t), integrationKey(t)
	genesis, err := community.NewGenesis(roomKey, nodeKey, time.Now(), "Room", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Initialize(ctx, genesis, roomKey); err != nil {
		t.Fatal(err)
	}
	address := integrationAddress(t)
	runtime, err := New(Config{
		Key: nodeKey, Listen: address, Socket: filepath.Join(t.TempDir(), "node.sock"),
		Genesis: &genesis, Store: database, RoomKey: roomKey, NodeRole: community.NodeRoleSequencer,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	session, err := replica.DialSequencer(ctx, replica.Config{
		RoomID: genesis.RoomKey, NodeKey: identityKey, DirectAddress: address,
		DirectPublic: nodeKey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	proposal, err := community.SignProposal(identityKey, genesis.NodeKey, community.EventProposal{
		RoomID: genesis.RoomKey, AuthorName: "alice", Nonce: nonce, Timestamp: time.Now().Unix(),
		Body: community.EventMessage{Text: "hello"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var response any
	if err := session.Peer.Query(ctx, community.SubmitEvent{Proposal: proposal}, &response); err != nil {
		t.Fatal(err)
	}
	accepted, ok := response.(community.SubmitAccepted)
	if !ok || accepted.Event.Seqno != 1 {
		t.Fatalf("response = %#v", response)
	}

	forgedKey := integrationKey(t)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	forged, err := community.SignProposal(forgedKey, genesis.NodeKey, community.EventProposal{
		RoomID: genesis.RoomKey, Nonce: nonce, Timestamp: time.Now().Unix(), Body: community.EventMessage{Text: "forged"},
	})
	if err != nil {
		t.Fatal(err)
	}
	response = nil
	if err := session.Peer.Query(ctx, community.SubmitEvent{Proposal: forged}, &response); err != nil {
		t.Fatal(err)
	}
	rejected, ok := response.(community.SubmitRejected)
	if !ok || rejected.Code != community.RejectPermissionDenied {
		t.Fatalf("forged response = %#v", response)
	}

	replicaStore, err := store.Open(ctx, filepath.Join(t.TempDir(), "replica.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer replicaStore.Close()
	if err := replicaStore.InitializeReplica(ctx, genesis); err != nil {
		t.Fatal(err)
	}
	synced, err := replica.Sync(ctx, replica.Config{
		RoomID: genesis.RoomKey, NodeKey: integrationKey(t), DirectAddress: address,
		DirectPublic: nodeKey.Public().(ed25519.PublicKey),
	}, replicaStore)
	if err != nil {
		t.Fatal(err)
	}
	if synced.Head.Seqno != 1 {
		t.Fatalf("replica head = %d, want 1", synced.Head.Seqno)
	}
}
