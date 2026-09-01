package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"
	"time"

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

func TestIdentityADNLAuthorsProposalWithoutBinding(t *testing.T) {
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
	if err := session.Overlay.Query(ctx, community.SubmitEvent{Proposal: proposal}, &response); err != nil {
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
	if err := session.Overlay.Query(ctx, community.SubmitEvent{Proposal: forged}, &response); err != nil {
		t.Fatal(err)
	}
	rejected, ok := response.(community.SubmitRejected)
	if !ok || rejected.Code != community.RejectPermissionDenied {
		t.Fatalf("forged response = %#v", response)
	}
}
