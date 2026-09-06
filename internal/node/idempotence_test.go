package node

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

func TestDuplicateSurvivesDNSChange(t *testing.T) {
	ctx := context.Background()
	roomKey, nodeKey, authorKey := integrationKey(t), integrationKey(t), integrationKey(t)
	now := time.Now()
	genesis, err := community.NewGenesis(roomKey, nodeKey, now, "Room", "", true, nil)
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
	proposal, err := community.SignProposal(authorKey, genesis.NodeKey, community.EventProposal{RoomID: genesis.RoomKey, AuthorDomain: "audit.ton", Nonce: make([]byte, 32), Timestamp: now.Unix(), Body: community.EventMessage{Text: "committed"}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Node{genesis: genesis, store: database, roomKey: roomKey, domainCache: make(map[string]identityDomainCache)}
	lookups := 0
	runtime.resolveIdentity = func(context.Context, string) ([]byte, error) { lookups++; return proposal.AuthorKey, nil }
	if _, err := runtime.commitProposal(ctx, proposal, now); err != nil {
		t.Fatal(err)
	}
	runtime.resolveIdentity = func(context.Context, string) ([]byte, error) { lookups++; return nil, errors.New("DNS unavailable") }
	duplicate, err := runtime.commitProposal(ctx, proposal, now.Add(6*time.Minute))
	if err != nil || !duplicate.Duplicate || duplicate.Event.Seqno != 1 || lookups != 1 {
		t.Fatalf("duplicate rejected or DNS repeated: %#v %v lookups=%d", duplicate, err, lookups)
	}
	proposal.Nonce[0] = 1
	if _, err := runtime.commitProposal(ctx, proposal, now); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if lookups != 1 {
		t.Fatal("DNS invoked for invalid signature")
	}
}

func TestConcurrentDuplicateWinsOverDNSFailure(t *testing.T) {
	ctx := context.Background()
	roomKey, nodeKey := integrationKey(t), integrationKey(t)
	now := time.Now()
	genesis, err := community.NewGenesis(roomKey, nodeKey, now, "Room", "", true, nil)
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
	proposal, err := community.SignProposal(roomKey, genesis.NodeKey, community.EventProposal{RoomID: genesis.RoomKey, AuthorDomain: "audit.ton", Nonce: make([]byte, 32), Timestamp: now.Unix(), Body: community.EventMessage{Text: "committed"}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Node{genesis: genesis, store: database, roomKey: roomKey, domainCache: make(map[string]identityDomainCache)}
	runtime.resolveIdentity = func(context.Context, string) ([]byte, error) {
		if _, err := database.Commit(ctx, proposal, roomKey, now); err != nil {
			return nil, err
		}
		return nil, errors.New("DNS unavailable")
	}
	result, err := runtime.commitProposal(ctx, proposal, now)
	if err != nil || !result.Duplicate {
		t.Fatalf("concurrent duplicate lost: %#v %v", result, err)
	}
}
