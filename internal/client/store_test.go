package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

func TestClientStoreValidatesRoomStateRevision(t *testing.T) {
	ctx := context.Background()
	store, err := openClientStore(ctx, filepath.Join(t.TempDir(), "client.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	now := time.Now().UTC().Truncate(time.Second)
	room := clientTestPrivateKey(t)
	node := clientTestPrivateKey(t)
	genesis, err := community.NewGenesis(room, node, now, "Room", "Description", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.addRoom(ctx, genesis.RoomKey, "room", nil); err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	proposal, err := community.SignProposal(room, genesis.NodeKey, community.EventProposal{
		RoomID: genesis.RoomKey, Nonce: nonce, Timestamp: now.Unix(),
		Body: community.EventMetadata{Name: "Updated", Description: "Current"},
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := community.SignCommit(room, proposal, 1, community.Zero256(), now)
	if err != nil {
		t.Fatal(err)
	}
	if inserted, err := store.appendEvent(ctx, genesis.RoomKey, event); err != nil || !inserted {
		t.Fatalf("append event: inserted=%v err=%v", inserted, err)
	}
	eventHash, err := event.Hash()
	if err != nil {
		t.Fatal(err)
	}
	current, err := community.SignRoomState(room, community.RoomState{
		RoomID: genesis.RoomKey, RevisionSeqno: 1, RevisionHash: eventHash,
		Name: "Updated", Description: "Current", WritePolicy: genesis.WritePolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.validateRoomState(ctx, genesis.RoomKey, genesis, current); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}

	genesisHash, err := genesis.Hash()
	if err != nil {
		t.Fatal(err)
	}
	stale, err := community.SignRoomState(room, community.RoomState{
		RoomID: genesis.RoomKey, RevisionHash: genesisHash,
		Name: genesis.Name, Description: genesis.Description, WritePolicy: genesis.WritePolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.validateRoomState(ctx, genesis.RoomKey, genesis, stale); err == nil {
		t.Fatal("stale state accepted")
	}

	otherRoom := clientTestPrivateKey(t)
	otherHash := make([]byte, 32)
	wrongRoom, err := community.SignRoomState(otherRoom, community.RoomState{
		RoomID: otherRoom.Public().(ed25519.PublicKey), RevisionHash: otherHash,
		Name: "Other", Description: "Other", WritePolicy: genesis.WritePolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.validateRoomState(ctx, genesis.RoomKey, genesis, wrongRoom); err == nil {
		t.Fatal("state from another room accepted")
	}
}

func clientTestPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private
}
