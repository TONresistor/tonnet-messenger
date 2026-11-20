package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

type inboxPushReceiver struct {
	peer *roomnet.Peer
	data chan any
}

func newInboxPushReceiver(t *testing.T, ctx context.Context, n *Node, key ed25519.PrivateKey) inboxPushReceiver {
	t.Helper()
	r := inboxPushReceiver{peer: inboxPeer(t, ctx, n, key), data: make(chan any, 64)}
	r.peer.SetMessageHandler(func(value any) error { r.data <- value; return nil })
	return r
}

func (r inboxPushReceiver) take(t *testing.T, ctx context.Context) any {
	t.Helper()
	select {
	case value := <-r.data:
		return value
	case <-ctx.Done():
		t.Fatal("missing queued message", ctx.Err())
		return nil
	}
}

func (r inboxPushReceiver) noMessage(t *testing.T) {
	t.Helper()
	select {
	case value := <-r.data:
		t.Fatalf("unexpected push/message: %#v", value)
	case <-time.After(80 * time.Millisecond):
	}
}

func pushDeposit(t *testing.T, ctx context.Context, p *roomnet.Peer, request community.InboxDepositV1) community.InboxReceiptV1 {
	t.Helper()
	var receipt community.InboxReceiptV1
	if err := p.Query(ctx, request, &receipt); err != nil || receipt.Verify() != nil {
		t.Fatal("deposit receipt", err)
	}
	return receipt
}

func pushPage(t *testing.T, ctx context.Context, p *roomnet.Peer, proof community.InboxAuthV1, after int64, limit int32) community.InboxPageV1 {
	t.Helper()
	var page community.InboxPageV1
	if err := p.Query(ctx, community.GetInboxV1{Auth: proof, After: after, Limit: limit}, &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func requireInboxPush(t *testing.T, ctx context.Context, r inboxPushReceiver, seqno int64, message community.DirectMessageV3) {
	t.Helper()
	value := r.take(t, ctx)
	push, ok := value.(community.InboxPushV1)
	if !ok || push.Seqno != seqno {
		t.Fatalf("push = %#v, want seqno %d", value, seqno)
	}
	want, _ := community.Encode(message)
	got, _ := community.Encode(push.Message)
	if !bytes.Equal(want, got) {
		t.Fatal("push envelope changed")
	}
}

func TestInboxPushSubscriptionPagesReplacementAndDuplicates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, false)
	sender, a, b := integrationKey(t), integrationKey(t), integrationKey(t)
	p := inboxPeer(t, ctx, f.n, sender)
	r := newInboxPushReceiver(t, ctx, f.n, integrationKey(t))
	deposit := func(recipient ed25519.PrivateKey, nonce byte) community.InboxDepositV1 {
		q := inboxDeposit(t, sender, recipient, nonce, time.Now().Unix()+300)
		pushDeposit(t, ctx, p, q)
		return q
	}
	deposit(a, 1)
	proofA := inboxAuth(t, f.n, a, challenge(t, ctx, r.peer, inboxID(t, a)))
	var ack community.InboxAckedV1
	if err := r.peer.Query(ctx, community.InboxAckV1{Auth: proofA}, &ack); err != nil {
		t.Fatal(err)
	}
	bad := proofA
	bad.Signature = bytes.Clone(proofA.Signature)
	bad.Signature[0] ^= 1
	var rejected community.InboxPageRejectedV1
	if err := r.peer.Query(ctx, community.GetInboxV1{Auth: bad}, &rejected); err != nil || rejected.Code != 18 {
		t.Fatal("failed proof", rejected, err)
	}
	deposit(a, 2)
	if page := pushPage(t, ctx, r.peer, proofA, 0, 1); !page.HasMore || page.LastSeqno != 1 {
		t.Fatal("expected nonterminal page", page)
	}
	deposit(a, 3)
	r.noMessage(t) // Neither challenge, ack, failed nor nonterminal page subscribed.
	if page := pushPage(t, ctx, r.peer, proofA, 1, 100); page.HasMore || page.LastSeqno != 3 {
		t.Fatal("terminal page", page)
	}
	four := deposit(a, 4)
	requireInboxPush(t, ctx, r, 4, four.Message)
	receipt := pushDeposit(t, ctx, p, four)
	if err := r.peer.Query(ctx, community.InboxAckV1{Auth: proofA, IDs: [][]byte{receipt.DMID}}, &ack); err != nil || ack.Deleted != 1 {
		t.Fatal("pushed message was not retained for ack", err)
	}
	if page := pushPage(t, ctx, r.peer, proofA, 3, 100); len(page.Messages) != 0 || page.LastSeqno != 3 {
		t.Fatal("push moved fetch cursor", page)
	}
	proofB := inboxAuth(t, f.n, b, challenge(t, ctx, r.peer, inboxID(t, b)))
	if err := r.peer.Query(ctx, community.InboxAckV1{Auth: proofB}, &ack); err != nil {
		t.Fatal(err)
	}
	if err := r.peer.Query(ctx, community.GetInboxV1{Auth: bad}, &rejected); err != nil || rejected.Code != 18 {
		t.Fatal("failed page", err)
	}
	five := deposit(a, 5)
	requireInboxPush(t, ctx, r, 5, five.Message) // Challenge/ack/failure kept A.
	pushPage(t, ctx, r.peer, proofB, 0, 100)     // Empty terminal page replaces A with B.
	if page := pushPage(t, ctx, r.peer, proofA, 0, 1); !page.HasMore {
		t.Fatal("expected nonterminal A page")
	}
	deposit(a, 6)
	oneB := deposit(b, 7)
	requireInboxPush(t, ctx, r, 1, oneB.Message)
	if page := pushPage(t, ctx, r.peer, proofB, 0, 100); len(page.Messages) != 1 || page.LastSeqno != 1 {
		t.Fatal("push deleted a message", page)
	}
	receiptB := pushDeposit(t, ctx, p, oneB)
	if err := r.peer.Query(ctx, community.InboxAckV1{Auth: proofB, IDs: [][]byte{receiptB.DMID}}, &ack); err != nil || ack.Deleted != 1 {
		t.Fatal("ack after push", err)
	}
	oneB.Tier = 99
	pushDeposit(t, ctx, p, oneB) // Retained tombstone: no second push/debit.
	badDeposit := inboxDeposit(t, sender, b, 8, time.Now().Unix()+300)
	badDeposit.Tier = 1
	var tier community.InboxRejectedV1
	if err := p.Query(ctx, badDeposit, &tier); err != nil || tier.Code != 17 {
		t.Fatal("rejected deposit", tier, err)
	}
	r.noMessage(t)
}

func TestInboxPushPageDepositConcurrencyHasNoHoles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, false)
	sender, recipient := integrationKey(t), integrationKey(t)
	p := inboxPeer(t, ctx, f.n, sender)
	r := newInboxPushReceiver(t, ctx, f.n, integrationKey(t))
	proof := inboxAuth(t, f.n, recipient, challenge(t, ctx, r.peer, inboxID(t, recipient)))
	requests := []community.InboxDepositV1{
		inboxDeposit(t, sender, recipient, 1, time.Now().Unix()+300),
		inboxDeposit(t, sender, recipient, 2, time.Now().Unix()+300),
	}
	start := make(chan struct{})
	errs := make(chan error, 3)
	var page community.InboxPageV1
	go func() { <-start; errs <- r.peer.Query(ctx, community.GetInboxV1{Auth: proof}, &page) }()
	for _, request := range requests {
		go func() {
			<-start
			var receipt community.InboxReceiptV1
			errs <- p.Query(ctx, request, &receipt)
		}()
	}
	close(start)
	for i := 0; i < 3; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if page.HasMore || page.LastSeqno != int64(len(page.Messages)) {
		t.Fatal("terminal page cursor", page)
	}
	seen := make(map[string]bool)
	for _, message := range page.Messages {
		id, _ := community.HashBoxed(message)
		seen[string(id)] = true
	}
	seqnos := make(map[int64]bool)
	for i := len(page.Messages); i < 2; i++ {
		push, ok := r.take(t, ctx).(community.InboxPushV1)
		// Individual incoming streams may complete out of order. Admission
		// order is checked directly on the shared queue in the saturation test.
		if !ok || push.Seqno <= page.LastSeqno || push.Seqno > 2 || seqnos[push.Seqno] {
			t.Fatalf("push sequence after page %d: %#v", page.LastSeqno, push)
		}
		seqnos[push.Seqno] = true
		id, _ := community.HashBoxed(push.Message)
		if seen[string(id)] {
			t.Fatal("deposit appeared both in page and push")
		}
		seen[string(id)] = true
	}
	for _, request := range requests {
		id, _ := community.HashBoxed(request.Message)
		if !seen[string(id)] {
			t.Fatal("deposit lost between page and subscription")
		}
	}
	r.noMessage(t)
}

func TestInboxPushCanPrecedeSubscribingPageAnswer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, false)
	sender, recipient, transport := integrationKey(t), integrationKey(t), integrationKey(t)
	p := inboxPeer(t, ctx, f.n, sender)
	r := newInboxPushReceiver(t, ctx, f.n, transport)
	proof := inboxAuth(t, f.n, recipient, challenge(t, ctx, r.peer, inboxID(t, recipient)))
	managed, _ := f.n.peers.get(outboundTestID(transport.Public().(ed25519.PublicKey)))
	ready, release := make(chan struct{}), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	// The fixture delays only the answered stream's return to the transport.
	// Subscription installation and all admission run through the real handler.
	managed.conn.SetQueryHandler(func(q *roomnet.Query) error {
		err := f.n.answerQuery(managed, q)
		close(ready)
		select {
		case <-release:
		case <-q.Context().Done():
		}
		return err
	})
	var page community.InboxPageV1
	done := make(chan error, 1)
	go func() { done <- r.peer.Query(ctx, community.GetInboxV1{Auth: proof}, &page) }()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	request := inboxDeposit(t, sender, recipient, 1, time.Now().Unix()+300)
	pushDeposit(t, ctx, p, request)
	requireInboxPush(t, ctx, r, 1, request.Message)
	select {
	case err := <-done:
		t.Fatal("page answer unexpectedly completed before push", err)
	default:
	}
	close(release)
	released = true
	if err := <-done; err != nil || len(page.Messages) != 0 || page.LastSeqno != 0 || page.HasMore {
		t.Fatal("subscribing page changed after the later deposit", page, err)
	}
}

func TestInboxPushExpiryAndSameKeyReconnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f := freeInboxNode(t, 2*time.Second, true)
	sender, recipient, transport := integrationKey(t), integrationKey(t), integrationKey(t)
	p := inboxPeer(t, ctx, f.n, sender)
	r := newInboxPushReceiver(t, ctx, f.n, transport)
	c := challenge(t, ctx, r.peer, inboxID(t, recipient))
	proof := inboxAuth(t, f.n, recipient, c)
	pushPage(t, ctx, r.peer, proof, 0, 100)
	_, release := blockInboxQueue(t, ctx, f.n, transport)
	defer func() {
		if release != nil {
			release()
		}
	}()
	pushDeposit(t, ctx, p, inboxDeposit(t, sender, recipient, 1, time.Now().Unix()+300))
	timer := time.NewTimer(time.Until(time.Unix(c.ExpireAt, 0)) + 10*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	release()
	release = nil
	if wrapper, ok := broadcast.AsBroadcast(r.take(t, ctx)); !ok || wrapper.VerifyLive(time.Now()) != nil {
		t.Fatal("missing shared room broadcast")
	}
	pushDeposit(t, ctx, p, inboxDeposit(t, sender, recipient, 2, time.Now().Unix()+300))
	r.noMessage(t)
	proof = inboxAuth(t, f.n, recipient, challenge(t, ctx, r.peer, inboxID(t, recipient)))
	if page := pushPage(t, ctx, r.peer, proof, 0, 100); len(page.Messages) != 2 {
		t.Fatal("expired subscription lost stored message")
	}
	replacement := newInboxPushReceiver(t, ctx, f.n, transport)
	var rejected community.InboxPageRejectedV1
	if err := replacement.peer.Query(ctx, community.GetInboxV1{Auth: proof}, &rejected); err != nil || rejected.Code != 18 {
		t.Fatal("new physical connection inherited proof", rejected, err)
	}
	pushDeposit(t, ctx, p, inboxDeposit(t, sender, recipient, 3, time.Now().Unix()+300))
	replacement.noMessage(t)
	proof = inboxAuth(t, f.n, recipient, challenge(t, ctx, replacement.peer, inboxID(t, recipient)))
	if page := pushPage(t, ctx, replacement.peer, proof, 0, 100); len(page.Messages) != 3 {
		t.Fatal("reconnect lost retained messages")
	}
	four := inboxDeposit(t, sender, recipient, 4, time.Now().Unix()+300)
	pushDeposit(t, ctx, p, four)
	requireInboxPush(t, ctx, replacement, 4, four.Message)
	r.noMessage(t)
}

func roomQueueMarker(t *testing.T, n *Node, marker byte) broadcast.Broadcast {
	t.Helper()
	message, err := broadcast.Sign(n.room.roomKey, nil, []byte{marker}, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	return message
}

// Block the existing room writer with its ordinary outbound lock. Push jobs
// must wait behind it on this very same channel; there is no push-only queue.
func blockInboxQueue(t *testing.T, ctx context.Context, n *Node, transport ed25519.PrivateKey) (*peer, func()) {
	t.Helper()
	p, ok := n.peers.get(outboundTestID(transport.Public().(ed25519.PublicKey)))
	if !ok {
		t.Fatal("missing managed peer")
	}
	p.outboundMu.Lock()
	if !n.enqueue(p, roomQueueMarker(t, n, 1)) {
		p.outboundMu.Unlock()
		t.Fatal("room enqueue failed")
	}
	for len(p.out) != 0 {
		select {
		case <-ctx.Done():
			p.outboundMu.Unlock()
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	return p, p.outboundMu.Unlock
}

func TestInboxPushSharesRoomQueueAndDiscardsReplacedSubscription(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, true)
	sender, a, b, transport := integrationKey(t), integrationKey(t), integrationKey(t), integrationKey(t)
	p := inboxPeer(t, ctx, f.n, sender)
	r := newInboxPushReceiver(t, ctx, f.n, transport)
	proofA := inboxAuth(t, f.n, a, challenge(t, ctx, r.peer, inboxID(t, a)))
	pushPage(t, ctx, r.peer, proofA, 0, 100)
	_, release := blockInboxQueue(t, ctx, f.n, transport)
	defer func() {
		if release != nil {
			release()
		}
	}()
	pushDeposit(t, ctx, p, inboxDeposit(t, sender, a, 1, time.Now().Unix()+300))
	proofB := inboxAuth(t, f.n, b, challenge(t, ctx, r.peer, inboxID(t, b)))
	pushPage(t, ctx, r.peer, proofB, 0, 100)
	oneB := inboxDeposit(t, sender, b, 2, time.Now().Unix()+300)
	pushDeposit(t, ctx, p, oneB)
	release()
	release = nil
	// Streams may complete in either order, but both messages use one writer.
	for i := 0; i < 2; i++ {
		value := r.take(t, ctx)
		if wrapper, ok := broadcast.AsBroadcast(value); ok && bytes.Equal(wrapper.Data, []byte{1}) && wrapper.VerifyLive(time.Now()) == nil {
			continue
		}
		push, ok := value.(community.InboxPushV1)
		if !ok || push.Seqno != 1 || !bytes.Equal(push.Message.ToKey, oneB.Message.ToKey) {
			t.Fatalf("wrong shared queued message: %#v", value)
		}
	}
	r.noMessage(t)
	if page := pushPage(t, ctx, r.peer, proofA, 0, 100); len(page.Messages) != 1 {
		t.Fatal("discarded queued push deleted A")
	}
}

func TestInboxPushSharedQueueFullClosesOnlyPhysicalTargetAndKeepsDeposits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, true)
	sender, recipient, transport := integrationKey(t), integrationKey(t), integrationKey(t)
	p := inboxPeer(t, ctx, f.n, sender)
	r := newInboxPushReceiver(t, ctx, f.n, transport)
	proof := inboxAuth(t, f.n, recipient, challenge(t, ctx, r.peer, inboxID(t, recipient)))
	pushPage(t, ctx, r.peer, proof, 0, 100)
	managed, release := blockInboxQueue(t, ctx, f.n, transport)
	defer func() {
		if release != nil {
			release()
		}
	}()
	var physical *roomnet.Connection
	var sub *inboxSubscription
	f.n.inbox.mu.Lock()
	for conn, state := range f.n.inbox.connections {
		if state.subscription != nil && state.subscription.peer == managed {
			physical, sub = conn, state.subscription
		}
	}
	f.n.inbox.mu.Unlock()
	if physical == nil || cap(managed.out) != outboundQueueCap {
		t.Fatal("missing physical target/shared queue")
	}
	if !f.n.enqueue(managed, roomQueueMarker(t, f.n, 2)) {
		t.Fatal("second room message failed")
	}
	var last community.InboxDepositV1
	var receipt community.InboxReceiptV1
	for i := 0; i < outboundQueueCap; i++ {
		last = inboxDeposit(t, sender, recipient, byte(i+1), time.Now().Unix()+300)
		receipt = pushDeposit(t, ctx, p, last)
		if i < outboundQueueCap-1 && len(managed.out) != i+2 {
			t.Fatal("room and push messages used different queues")
		}
	}
	select {
	case <-physical.Context().Done():
	case <-ctx.Done():
		t.Fatal("full queue did not close physical connection")
	}
	if f.n.stats.slowPeerDisconnects.Load() != 1 {
		t.Fatal("shared queue overflow not recorded")
	}
	// The blocked room writer leaves its second broadcast followed by the
	// first 31 deposits on the one channel, in durable seqno order.
	for i := 0; i < outboundQueueCap; i++ {
		job := <-managed.out
		if i == 0 {
			if _, ok := broadcast.AsBroadcast(job.items[0]); !ok || job.physical != nil {
				t.Fatal("missing shared room job")
			}
		} else if push, ok := job.items[0].(community.InboxPushV1); !ok || push.Seqno != int64(i) || job.physical != physical {
			t.Fatalf("push queue order/target at %d: %#v", i, job)
		}
	}
	replacement := newInboxPushReceiver(t, ctx, f.n, transport)
	// A stale job must neither fall back nor close this new same-key path.
	f.n.enqueueInbox(managed, physical, sub, community.InboxPushV1{Seqno: 99, Message: last.Message})
	var caps community.Capabilities
	if err := replacement.peer.Query(ctx, community.GetCapabilities{}, &caps); err != nil || caps.Flags != community.RelayServiceDM {
		t.Fatal("old queue target closed replacement or enabled flags", err)
	}
	release()
	release = nil
	proof = inboxAuth(t, f.n, recipient, challenge(t, ctx, replacement.peer, inboxID(t, recipient)))
	if page := pushPage(t, ctx, replacement.peer, proof, 0, 100); len(page.Messages) != outboundQueueCap || page.LastSeqno != outboundQueueCap {
		t.Fatal("queue overflow lost committed deposits", page)
	}
	duplicate := pushDeposit(t, ctx, p, last)
	want, _ := community.Encode(receipt)
	got, _ := community.Encode(duplicate)
	if !bytes.Equal(want, got) {
		t.Fatal("queue overflow changed durable receipt")
	}
	replacement.noMessage(t)
}
