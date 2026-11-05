package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/control"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

type inboxNodeFixture struct {
	n    *Node
	db   *store.Store
	path string
	room *community.Genesis
}

func freeInboxNode(t *testing.T, ttl time.Duration, combined bool) *inboxNodeFixture {
	t.Helper()
	dir, err := os.MkdirTemp("", "tn-inbox-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &inboxNodeFixture{path: filepath.Join(dir, "node.db")}
	f.db, err = store.Open(context.Background(), f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Close() })
	cfg := Config{Key: integrationKey(t), Listen: integrationAddress(t), Socket: filepath.Join(dir, "node.sock"), Store: f.db, LocalOnly: true, DM: &DMConfig{ChallengeTTL: ttl, Limits: store.InboxLimits{Offer: &community.RelayOfferV1{Services: community.RelayServiceDM, MaxObjectBytes: 64 << 10, RetentionSeconds: 600, RequestsPerMinute: 100, InboxQuotaBytes: 1 << 20}, MaxMessages: 100, MaxBytes: 1 << 20}}}
	if combined {
		key := integrationKey(t)
		g, err := community.NewGenesis(key, cfg.Key, time.Now(), "Combined", "", true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.db.Initialize(context.Background(), g, key); err != nil {
			t.Fatal(err)
		}
		cfg.Genesis = &g
		cfg.RoomKey = key
		f.room = &g
	}
	f.n, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.n.Close() })
	return f
}

func inboxPeer(t *testing.T, ctx context.Context, n *Node, key ed25519.PrivateKey) *roomnet.Peer {
	t.Helper()
	g, err := roomnet.NewGateway(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	raw, err := g.DialDefault(ctx, n.cfg.Key.Public().(ed25519.PublicKey), n.cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	return roomnet.Wrap(raw)
}

func inboxID(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	id, err := community.KeyID(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func inboxDeposit(t *testing.T, sender, recipient ed25519.PrivateKey, nonce byte, expire int64) community.InboxDepositV1 {
	t.Helper()
	m, err := community.SignDirectMessageV3(sender, community.DirectMessageV3{ToKey: recipient.Public().(ed25519.PublicKey), CreatedAt: time.Now().Unix(), ExpireAt: expire, Ciphertext: bytes.Repeat([]byte{nonce}, 28)})
	if err != nil {
		t.Fatal(err)
	}
	return community.InboxDepositV1{Message: m}
}

func challenge(t *testing.T, ctx context.Context, peer *roomnet.Peer, id []byte) community.InboxChallengeV1 {
	t.Helper()
	var result community.InboxChallengeV1
	if err := peer.Query(ctx, community.GetInboxChallengeV1{InboxID: id}, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func inboxAuth(t *testing.T, n *Node, recipient ed25519.PrivateKey, c community.InboxChallengeV1) community.InboxAuthV1 {
	t.Helper()
	a, err := community.SignInboxAuthV1(recipient, community.InboxAuthV1ToSign{RelayKey: n.cfg.Key.Public().(ed25519.PublicKey), InboxID: inboxID(t, recipient), Nonce: c.Nonce, ExpireAt: c.ExpireAt})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestFreeInboxDepositsPagesAckAndDuplicateAfterReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, true)
	sender, recipient, other := integrationKey(t), integrationKey(t), integrationKey(t)
	p := inboxPeer(t, ctx, f.n, sender)
	expire := time.Now().Unix() + 300
	request := inboxDeposit(t, sender, recipient, 1, expire)
	for _, mode := range []string{"malformed", "signature", "tier"} {
		bad := request
		bad.Message.Signature = bytes.Clone(request.Message.Signature)
		code := int32(1)
		switch mode {
		case "malformed":
			bad.Message.Ciphertext = []byte{1}
		case "signature":
			bad.Message.Signature[0] ^= 1
			code = 5
		case "tier":
			bad.Tier = 1
			code = 17
		}
		var rejected community.InboxRejectedV1
		if err := p.Query(ctx, bad, &rejected); err != nil || rejected.Code != code {
			t.Fatalf("deposit %s: %+v %v", mode, rejected, err)
		}
	}
	var receipts []community.InboxReceiptV1
	for i := 0; i < 3; i++ {
		q := request
		if i > 0 {
			q = inboxDeposit(t, sender, recipient, byte(i+1), expire)
		}
		var receipt community.InboxReceiptV1
		if err := p.Query(ctx, q, &receipt); err != nil || receipt.Verify() != nil {
			t.Fatal("free deposit", err)
		}
		if !bytes.Equal(receipt.RelayKey, f.n.cfg.Key.Public().(ed25519.PublicKey)) || !bytes.Equal(receipt.InboxID, inboxID(t, recipient)) {
			t.Fatal("wrong receipt context")
		}
		receipts = append(receipts, receipt)
	}
	var foreign community.InboxReceiptV1
	if err := p.Query(ctx, inboxDeposit(t, sender, other, 9, expire), &foreign); err != nil {
		t.Fatal(err)
	}
	// Proof, not an extra TLS-key equality rule, authorizes fetch and ack.
	r := inboxPeer(t, ctx, f.n, integrationKey(t))
	proof := inboxAuth(t, f.n, recipient, challenge(t, ctx, r, inboxID(t, recipient)))
	var page community.InboxPageV1
	if err := r.Query(ctx, community.GetInboxV1{Auth: proof, Limit: 2}, &page); err != nil || len(page.Messages) != 2 || page.LastSeqno != 2 || !page.HasMore {
		t.Fatalf("page: %+v %v", page, err)
	}
	var ack community.InboxAckedV1
	if err := r.Query(ctx, community.InboxAckV1{Auth: proof, IDs: [][]byte{receipts[0].DMID, foreign.DMID}}, &ack); err != nil || ack.Deleted != 1 {
		t.Fatal("ack isolation", ack, err)
	}
	if err := r.Query(ctx, community.GetInboxV1{Auth: proof, After: 2}, &page); err != nil || len(page.Messages) != 1 || page.LastSeqno != 3 || page.HasMore {
		t.Fatal("cursor after deletion", err)
	}
	otherProof := inboxAuth(t, f.n, other, challenge(t, ctx, r, inboxID(t, other)))
	if err := r.Query(ctx, community.GetInboxV1{Auth: otherProof}, &page); err != nil || len(page.Messages) != 1 || page.LastSeqno != 1 {
		t.Fatal("ack deleted another inbox", err)
	}
	var malformed community.InboxPageRejectedV1
	if err := r.Query(ctx, community.GetInboxV1{Auth: proof, After: -1}, &malformed); err != nil || malformed.Code != 1 {
		t.Fatal("malformed page", err)
	}
	var malformedAck community.InboxAckRejectedV1
	ids := make([][]byte, 257)
	for i := range ids {
		ids[i] = community.Zero256()
	}
	if err := r.Query(ctx, community.InboxAckV1{Auth: proof, IDs: ids}, &malformedAck); err != nil || malformedAck.Code != 1 {
		t.Fatal("malformed ack", err)
	}
	if status := f.n.Status().Rooms[0]; status.Members != 0 || status.Neighbours != 0 {
		t.Fatal("inbox queries joined a room")
	}
	var caps community.Capabilities
	if err := r.Query(ctx, community.GetCapabilities{}, &caps); err != nil || caps.Flags != community.RelayServiceDM {
		t.Fatal("enabled service missing DM or advertising paid capability", err)
	}
	p.Close()
	p = inboxPeer(t, ctx, f.n, sender)
	request.Tier = 99
	var duplicate community.InboxReceiptV1
	if err := p.Query(ctx, request, &duplicate); err != nil {
		t.Fatal(err)
	}
	want, _ := community.Encode(receipts[0])
	got, _ := community.Encode(duplicate)
	if !bytes.Equal(want, got) {
		t.Fatal("reconnect duplicate changed persisted receipt")
	}
	wrongPeer := inboxPeer(t, ctx, f.n, integrationKey(t))
	var rejected community.InboxRejectedV1
	if err := wrongPeer.Query(ctx, request, &rejected); err != nil || rejected.Code != 5 {
		t.Fatal("duplicate skipped authenticated sender equality", err)
	}
}

func TestInboxProofContextAndPhysicalConnectionIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, false)
	recipient, transport := integrationKey(t), integrationKey(t)
	first := inboxPeer(t, ctx, f.n, transport)
	c := challenge(t, ctx, first, inboxID(t, recipient))
	proof := inboxAuth(t, f.n, recipient, c)
	var page community.InboxPageV1
	if err := first.Query(ctx, community.GetInboxV1{Auth: proof}, &page); err != nil {
		t.Fatal("valid proof rejected", err)
	}
	for _, mode := range []string{"recipient", "relay", "inbox", "nonce", "expiry"} {
		bad := proof
		bad.Nonce = bytes.Clone(proof.Nonce)
		proofContext := community.InboxAuthV1ToSign{RelayKey: f.n.cfg.Key.Public().(ed25519.PublicKey), InboxID: inboxID(t, recipient), Nonce: c.Nonce, ExpireAt: c.ExpireAt}
		switch mode {
		case "recipient":
			bad.RecipientKey = integrationKey(t).Public().(ed25519.PublicKey)
		case "relay":
			proofContext.RelayKey = integrationKey(t).Public().(ed25519.PublicKey)
		case "inbox":
			proofContext.InboxID = inboxID(t, integrationKey(t))
		case "nonce":
			bad.Nonce[0] ^= 1
		case "expiry":
			proofContext.ExpireAt++
		}
		if mode == "relay" || mode == "inbox" || mode == "expiry" {
			hash, err := community.HashBoxed(proofContext)
			if err != nil {
				t.Fatal(err)
			}
			bad.Signature = ed25519.Sign(recipient, hash)
		}
		var rejected community.InboxPageRejectedV1
		if err := first.Query(ctx, community.GetInboxV1{Auth: bad}, &rejected); err != nil || rejected.Code != 18 {
			t.Fatalf("proof %s: %+v %v", mode, rejected, err)
		}
	}
	other := inboxPeer(t, ctx, f.n, integrationKey(t))
	var rejected community.InboxPageRejectedV1
	if err := other.Query(ctx, community.GetInboxV1{Auth: proof}, &rejected); err != nil || rejected.Code != 18 {
		t.Fatal("proof leaked to another connection", err)
	}
	id := outboundTestID(transport.Public().(ed25519.PublicKey))
	managed, _ := f.n.peers.get(id)
	replacement := inboxPeer(t, ctx, f.n, transport)
	if err := replacement.Query(ctx, community.GetInboxV1{Auth: proof}, &rejected); err != nil || rejected.Code != 18 {
		t.Fatal("same-key physical replacement retained proof", err)
	}
	if current, _ := f.n.peers.get(id); current != managed {
		t.Fatal("test did not exercise managed-path reuse")
	}
	fresh := inboxAuth(t, f.n, recipient, challenge(t, ctx, replacement, inboxID(t, recipient)))
	if err := replacement.Query(ctx, community.GetInboxV1{Auth: fresh}, &page); err != nil {
		t.Fatal("replacement could not establish its own proof", err)
	}
	f.n.inbox.mu.Lock()
	for conn := range f.n.inbox.connections {
		if conn.Context().Err() != nil {
			t.Error("closed physical connection retained challenge state")
		}
	}
	f.n.inbox.mu.Unlock()
	// Failed proof must be rejected before touching unavailable storage.
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	bad := fresh
	bad.Signature = bytes.Clone(fresh.Signature)
	bad.Signature[0] ^= 1
	if err := replacement.Query(ctx, community.GetInboxV1{Auth: bad}, &rejected); err != nil || rejected.Code != 18 {
		t.Fatal("failed proof reached page storage", err)
	}
	var ackRejected community.InboxAckRejectedV1
	if err := replacement.Query(ctx, community.InboxAckV1{Auth: bad, IDs: [][]byte{community.Zero256()}}, &ackRejected); err != nil || ackRejected.Code != 18 {
		t.Fatal("failed proof reached ack storage", err)
	}
}

func TestInboxChallengeCapExpiryAndCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, false)
	recipient := integrationKey(t)
	p := inboxPeer(t, ctx, f.n, integrationKey(t))
	var first community.InboxChallengeV1
	seen := make(map[string]bool)
	for i := 0; i < 4; i++ {
		c := challenge(t, ctx, p, inboxID(t, recipient))
		if seen[string(c.Nonce)] {
			t.Fatal("challenge nonce reused")
		}
		seen[string(c.Nonce)] = true
		if i == 0 {
			first = c
		}
	}
	var rejected community.InboxChallengeRejectedV1
	if err := p.Query(ctx, community.GetInboxChallengeV1{InboxID: inboxID(t, recipient)}, &rejected); err != nil || rejected.Code != 16 {
		t.Fatal("challenge cap", err)
	}

	expiry := freeInboxNode(t, time.Second, false)
	ep := inboxPeer(t, ctx, expiry.n, integrationKey(t))
	first = challenge(t, ctx, ep, inboxID(t, recipient))
	timer := time.NewTimer(time.Until(time.Unix(first.ExpireAt, 0)) + 10*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var expired community.InboxPageRejectedV1
	if err := ep.Query(ctx, community.GetInboxV1{Auth: inboxAuth(t, expiry.n, recipient, first)}, &expired); err != nil || expired.Code != 18 {
		t.Fatal("expired proof accepted", err)
	}
	challenge(t, ctx, ep, inboxID(t, recipient))
	expiry.n.inbox.mu.Lock()
	states := len(expiry.n.inbox.connections)
	expiry.n.inbox.mu.Unlock()
	if states != 1 {
		t.Fatal("expired challenge states were not bounded/cleaned")
	}
}

func TestInboxZeroAndCombinedLifecycleMaintenanceAndDisabledAdmission(t *testing.T) {
	for _, combined := range []bool{false, true} {
		t.Run(map[bool]string{false: "zero rooms", true: "combined"}[combined], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			f := freeInboxNode(t, 30*time.Second, combined)
			if !combined {
				f.n.cfg.LocalOnly = false
				f.n.cfg.Advertise = "1.1.1.1:17400"
				fakePublicRooms(f.n)
			}
			done := make(chan struct{})
			var runErr error
			go func() { runErr = f.n.Run(ctx); close(done) }()
			t.Cleanup(func() { cancel(); <-done })
			for {
				if status, err := control.Query(f.n.cfg.Socket); err == nil {
					want := 0
					if combined {
						want = 1
					}
					if len(status.Rooms) != want {
						t.Fatal("wrong shared control status")
					}
					break
				}
				select {
				case <-done:
					t.Fatal(runErr)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(time.Millisecond):
				}
			}
			sender, recipient := integrationKey(t), integrationKey(t)
			p := inboxPeer(t, ctx, f.n, sender)
			var clock broadcast.Time
			if err := p.Query(ctx, broadcast.GetTime{}, &clock); err != nil {
				t.Fatal(err)
			}
			if combined {
				var g community.Genesis
				if err := p.QueryRoom(ctx, f.room.RoomKey, community.GetRoomGenesis{}, &g); err != nil {
					t.Fatal("room traffic regressed", err)
				}
			}
			var receipt community.InboxReceiptV1
			if err := p.Query(ctx, inboxDeposit(t, sender, recipient, 1, time.Now().Unix()+2), &receipt); err != nil {
				t.Fatal(err)
			}
			read, err := sql.Open("sqlite", f.path)
			if err != nil {
				t.Fatal(err)
			}
			defer read.Close()
			for {
				var count int
				if err := read.QueryRow("SELECT COUNT(*) FROM inbox_messages").Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count == 0 {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("maintenance did not expire inbox", ctx.Err())
				case <-time.After(20 * time.Millisecond):
				}
			}
			if err := f.n.Close(); err != nil {
				t.Fatal(err)
			}
			<-done
			if !errors.Is(runErr, context.Canceled) {
				t.Fatal(runErr)
			}
			if _, err := f.db.PageInbox(context.Background(), inboxID(t, recipient), 0, 100, time.Now()); err != nil {
				t.Fatal("node closed the borrowed database", err)
			}
			f.n.inbox.mu.Lock()
			states := len(f.n.inbox.connections)
			f.n.inbox.mu.Unlock()
			if states != 0 {
				t.Fatal("shutdown retained proof state")
			}
		})
	}
	f := freeInboxNode(t, 30*time.Second, true)
	cfg := f.n.cfg
	cfg.Store = f.db
	cfg.Genesis = f.room
	cfg.RoomKey = f.n.room.roomKey
	cfg.NodeRole = community.NodeRoleSequencer
	cfg.Listen = integrationAddress(t)
	cfg.DM = nil
	disabled, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer disabled.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sender, recipient := integrationKey(t), integrationKey(t)
	peer := inboxPeer(t, ctx, disabled, sender)
	var rejected community.InboxRejectedV1
	if err := peer.Query(ctx, inboxDeposit(t, sender, recipient, 1, time.Now().Unix()+60), &rejected); err != nil || rejected.Code != 17 {
		t.Fatal("disabled service admitted DM", err)
	}
	if _, err := New(Config{Key: integrationKey(t), Store: f.db, Listen: integrationAddress(t), DM: &DMConfig{ChallengeTTL: time.Second}}); err == nil {
		t.Fatal("unbounded DM configuration accepted")
	}
}
