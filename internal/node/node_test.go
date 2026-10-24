package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/quic"
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
	for _, domain := range []string{"alice.ton", "team_member.t.me"} {
		t.Run(domain, func(t *testing.T) { testLocalSubmissionIdentityDomain(t, domain) })
	}
}

func testLocalSubmissionIdentityDomain(t *testing.T, domain string) {
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
		genesis: genesis, store: database, roomKey: roomKey, peers: newPeerTable(DefaultMaxLeaves),
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
			RoomID: genesis.RoomKey, AuthorDomain: domain, Nonce: nonce,
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

func TestBatchItemDistinguishesStorageAndRequestErrors(t *testing.T) {
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	runtime := &Node{store: database}
	for _, tc := range []struct {
		name    string
		request any
		code    int32
	}{
		{"events default limit", community.GetEvents{}, community.RejectPersistenceFailure},
		{"events maximum limit", community.GetEvents{Limit: community.MaxPageLimit}, community.RejectPersistenceFailure},
		{"recent messages", community.GetMessagesRecent{Limit: 1}, community.RejectPersistenceFailure},
		{"messages before", community.GetMessagesBefore{MessageID: 1, Limit: 1}, community.RejectPersistenceFailure},
		{"room state", community.GetRoomState{}, community.RejectPersistenceFailure},
		{"negative events limit", community.GetEvents{Limit: -1}, community.RejectMalformedRequest},
		{"excessive events limit", community.GetEvents{Limit: community.MaxPageLimit + 1}, community.RejectMalformedRequest},
		{"negative recent limit", community.GetMessagesRecent{Limit: -1}, community.RejectMalformedRequest},
		{"excessive recent limit", community.GetMessagesRecent{Limit: community.MaxPageLimit + 1}, community.RejectMalformedRequest},
		{"negative before limit", community.GetMessagesBefore{MessageID: 1, Limit: -1}, community.RejectMalformedRequest},
		{"excessive before limit", community.GetMessagesBefore{MessageID: 1, Limit: community.MaxPageLimit + 1}, community.RejectMalformedRequest},
		{"invalid message id", community.GetMessagesBefore{Limit: 1}, community.RejectMalformedRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := community.Encode(tc.request)
			if err != nil {
				t.Fatal(err)
			}
			item := runtime.batchItem(raw, time.Now())
			if item.Code != tc.code || len(item.Data) != 0 {
				t.Fatalf("batch item = %#v, want code %d with no data", item, tc.code)
			}
		})
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

func TestDirectMessageChecksSenderBeforeRateLimitAndMembership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connectionKey, otherKey := integrationKey(t), integrationKey(t)
	server, err := roomnet.NewGateway(connectionKey)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.SetConnectionHandler(func(*quic.Peer) error { return nil })
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	go server.Serve(packet)
	gateway, err := roomnet.NewGateway(integrationKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	rawPeer, err := gateway.DialDefault(ctx, connectionKey.Public().(ed25519.PublicKey), packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	connection := roomnet.Wrap(rawPeer)
	if !bytes.Equal(connection.GetPubKey(), connectionKey.Public().(ed25519.PublicKey)) {
		t.Fatal("connection has the wrong authenticated key")
	}
	roomKey, recipient := integrationKey(t), integrationKey(t)
	for _, mode := range []string{"mismatched leaf", "missing connection", "valid leaf", "healthy node forwarding"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			sender := otherKey
			p := newPeer("peer", kindLeaf, connection, nil)
			accepted := false
			switch mode {
			case "missing connection":
				p.conn = nil
			case "valid leaf":
				sender = connectionKey
				accepted = true
			case "healthy node forwarding":
				p.kind, p.state = kindNode, peerHealthy
				accepted = true
			}
			runtime := &Node{
				genesis: community.Genesis{RoomKey: roomKey.Public().(ed25519.PublicKey)},
				peers:   newPeerTable(DefaultMaxLeaves), sources: newSourceLimits(),
				messages: newTokenBucket(10, 0), penalties: newPenaltyBox(), dedup: overlay.NewDedup(10),
			}
			runtime.peers.m[p.id] = p
			direct, err := community.SignDirectMessage(sender, community.DirectMessage{
				RoomID: runtime.genesis.RoomKey, ToKey: recipient.Public().(ed25519.PublicKey),
				Timestamp: now.Unix(), Ciphertext: make([]byte, 28),
			})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := community.Encode(direct)
			if err != nil {
				t.Fatal(err)
			}
			wrapper, err := broadcast.Sign(sender, nil, raw, now.Unix())
			if err != nil {
				t.Fatal(err)
			}
			runtime.handleCommunityMessage(p, wrapper, now)
			_, limited := runtime.sources.m[hex.EncodeToString(direct.FromKey)]
			if limited != accepted || p.member != (accepted && p.kind == kindLeaf) {
				t.Fatalf("accepted=%v source limiter=%v member=%v", accepted, limited, p.member)
			}
			wantInvalid := uint64(1)
			if accepted {
				wantInvalid = 0
			}
			if got := runtime.stats.invalidDrops.Load(); got != wantInvalid {
				t.Fatalf("invalidDrops=%d, want %d", got, wantInvalid)
			}
			if runtime.dedup.Len() != 0 && !accepted || runtime.dedup.Len() != 1 && accepted {
				t.Fatalf("accepted=%v committed broadcasts=%d", accepted, runtime.dedup.Len())
			}
			if !accepted && (p.state != peerQuarantine || !p.lastGood.IsZero()) {
				t.Fatal("rejected sender changed peer health")
			}
		})
	}
}

func TestSequencerLinkRunsIndependentlyOfDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var calls atomic.Int32
	runtime := &Node{}
	runtime.runSequencerLink(ctx, func(context.Context) error { calls.Add(1); return nil }, 10*time.Millisecond)
	if calls.Load() < 2 {
		t.Fatal("authority link did not retry independently")
	}
}

func TestSequencerReconnectReplacesNodeAndPreservesClassification(t *testing.T) {
	table := newPeerTable(DefaultMaxLeaves)
	table.sequencerID = "authority"
	oldConn, newConn := &roomnet.Peer{}, &roomnet.Peer{}
	old, _, _ := table.addInbound("authority", oldConn)
	old.state = peerHealthy
	next, added, displaced := table.addInbound("authority", newConn)
	if !added || displaced != old || next == old || next.kind != kindNode || next.conn != newConn {
		t.Fatal("new authoritative connection was discarded")
	}
	if table.removePeer("authority", old) {
		t.Fatal("old disconnect callback removed its replacement")
	}
	if current, ok := table.get("authority"); !ok || current != next {
		t.Fatal("replacement disappeared")
	}
}
