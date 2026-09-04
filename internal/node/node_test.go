package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	"github.com/xssnick/tonutils-go/adnl/address"
)

func TestParseTONQUICAdvertiseAddress(t *testing.T) {
	endpoint, err := parseAddress("1.1.1.1:17400")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := endpoint.(*address.QUIC); !ok {
		t.Fatalf("endpoint type = %T, want TON QUIC", endpoint)
	}

	for _, invalid := range []string{
		"127.0.0.1:17400",
		"10.0.0.1:17400",
		"203.0.113.1:17400",
		"[2606:4700:4700::1111]:17400",
		"1.1.1.1:0",
		"1.1.1.1:65536",
	} {
		if _, err := parseAddress(invalid); err == nil {
			t.Errorf("parseAddress(%q) succeeded", invalid)
		}
	}
}

func TestLocalSubmissionVerifiesIdentityDomain(t *testing.T) {
	ctx := context.Background()
	roomKey, nodeKey, authorKey := integrationKey(t), integrationKey(t), integrationKey(t)
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
	runtime := &Node{
		store: database, roomKey: roomKey, peers: newPeerTable(DefaultMaxLeaves),
		domainCache: make(map[string]identityDomainCache),
		resolveIdentity: func(context.Context, string) ([]byte, error) {
			return integrationKey(t).Public().(ed25519.PublicKey), nil
		},
	}
	proposal := func(text string) []byte {
		t.Helper()
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		value, err := community.SignProposal(authorKey, genesis.NodeKey, community.EventProposal{
			RoomID: genesis.RoomKey, AuthorDomain: "alice.ton", Nonce: nonce,
			Timestamp: time.Now().Unix(), Body: community.EventMessage{Text: text},
		})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := community.Encode(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	responseRaw, err := runtime.submitLocal(ctx, proposal("rejected"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := community.DecodeAny(responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	rejected, ok := response.(community.SubmitRejected)
	if !ok || rejected.Code != community.RejectInvalidIdentityDomain {
		t.Fatalf("response = %#v", response)
	}
	head, err := database.Head(ctx)
	if err != nil || head.Seqno != 0 {
		t.Fatalf("head = %#v err=%v", head, err)
	}

	runtime.resolveIdentity = func(context.Context, string) ([]byte, error) {
		return authorKey.Public().(ed25519.PublicKey), nil
	}
	responseRaw, err = runtime.submitLocal(ctx, proposal("accepted"))
	if err != nil {
		t.Fatal(err)
	}
	response, err = community.DecodeAny(responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := response.(community.SubmitAccepted); !ok {
		t.Fatalf("response = %#v", response)
	}
}

func TestBatchResponseStaysWithinAnswerBudget(t *testing.T) {
	items := make([]community.BatchItem, community.MaxBatchQueries)
	for i := range items {
		items[i].Code = community.RejectLimitExceeded
	}
	accepted := 0
	for i := range items {
		if !setBatchItem(items, i, community.BatchItem{Data: bytes.Repeat([]byte{1}, 300*1024)}) {
			break
		}
		accepted++
	}
	if accepted == 0 || accepted == len(items) {
		t.Fatalf("accepted %d batch items", accepted)
	}
	encoded, err := community.Encode(community.BatchResult{Items: items})
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > roomnet.MaxAnswerPayloadSize {
		t.Fatalf("batch response = %d bytes, max %d", len(encoded), roomnet.MaxAnswerPayloadSize)
	}
	for _, item := range items[accepted:] {
		if item.Code != community.RejectLimitExceeded || len(item.Data) != 0 {
			t.Fatalf("overflow item = %#v", item)
		}
	}
}

func TestMessageLimitsAndSignaturePenaltyAreObservable(t *testing.T) {
	peer := newPeer("peer", kindLeaf, nil, nil)
	runtime := &Node{
		messages: newTokenBucket(1, 0), penalties: newPenaltyBox(),
	}
	runtime.handleCommunityMessage(peer, broadcast.Time{}, time.Now())
	runtime.handleCommunityMessage(peer, broadcast.Time{}, time.Now())
	if runtime.stats.invalidDrops.Load() != 1 || runtime.stats.globalRateDrops.Load() != 1 {
		t.Fatalf("stats invalid/global = %d/%d", runtime.stats.invalidDrops.Load(), runtime.stats.globalRateDrops.Load())
	}

	signer := integrationKey(t)
	wrapper, err := broadcast.Sign(signer, nil, []byte("payload"), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	wrapper.Signature[0] ^= 1
	runtime.messages = newTokenBucket(1, 0)
	runtime.handleCommunityMessage(peer, wrapper, time.Now())
	if !runtime.penalties.banned(peer.id, time.Now()) {
		t.Fatal("invalid signature did not penalize peer")
	}
}
