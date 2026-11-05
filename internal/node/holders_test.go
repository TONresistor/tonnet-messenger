package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
)

type holderWrite struct {
	key []byte
	at  time.Time
}
type holderTestPublisher struct {
	fakeRoomPublisher
	mu                sync.Mutex
	seeds             map[string][]tonoverlay.Node
	addresses         map[string]string
	keys              map[string]ed25519.PublicKey
	writes            []holderWrite
	fail              bool
	blockResolve      bool
	blocked           chan struct{}
	blockOnce         sync.Once
	ownerClosed, late atomic.Bool
}

func newHolderTestPublisher() *holderTestPublisher {
	return &holderTestPublisher{fakeRoomPublisher: fakeRoomPublisher{started: make(chan struct{}), stopped: make(chan struct{})}, seeds: make(map[string][]tonoverlay.Node), addresses: make(map[string]string), keys: make(map[string]ed25519.PublicKey), blocked: make(chan struct{})}
}
func (p *holderTestPublisher) FindOverlayNodes(ctx context.Context, key []byte) (*tonoverlay.NodesList, error) {
	p.finds.Add(1)
	p.mu.Lock()
	list := append([]tonoverlay.Node(nil), p.seeds[string(key)]...)
	p.mu.Unlock()
	return &tonoverlay.NodesList{List: list}, ctx.Err()
}
func (p *holderTestPublisher) ResolveAll(ctx context.Context, id []byte) ([]string, ed25519.PublicKey, error) {
	p.resolves.Add(1)
	if p.blockResolve {
		p.blockOnce.Do(func() { close(p.blocked) })
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return []string{p.addresses[string(id)]}, p.keys[string(id)], ctx.Err()
}
func (p *holderTestPublisher) PublishOverlay(ctx context.Context, key []byte, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.ownerClosed.Load() {
		p.late.Store(true)
		return errors.New("DHT owner already closed")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return errors.New("DHT write failed")
	}
	p.writes = append(p.writes, holderWrite{bytes.Clone(key), now})
	return nil
}
func (p *holderTestPublisher) count() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.writes) }
func (p *holderTestPublisher) endpoint(n *Node) {
	id, _ := community.KeyID(n.cfg.Key.Public().(ed25519.PublicKey))
	p.addresses[string(id)], p.keys[string(id)] = n.cfg.Listen, n.cfg.Key.Public().(ed25519.PublicKey)
}

func TestHolderMembershipTracksLiveMessagesAndLeavesSubscription(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, combined := range []bool{false, true} {
		f := freeInboxNode(t, 30*time.Second, combined)
		sender, recipient, transport := integrationKey(t), integrationKey(t), integrationKey(t)
		p := inboxPeer(t, ctx, f.n, sender)
		r := newInboxPushReceiver(t, ctx, f.n, transport)
		inbox := inboxID(t, recipient)
		id, _ := ov.InboxID(inbox)
		proof := inboxAuth(t, f.n, recipient, challenge(t, ctx, r.peer, inbox))
		pushPage(t, ctx, r.peer, proof, 0, 100)
		if f.n.holders.lookup(id, time.Now()) != nil {
			t.Fatal("subscription invented holder membership")
		}
		request := inboxDeposit(t, sender, recipient, 1, time.Now().Unix()+300)
		receipt := pushDeposit(t, ctx, p, request)
		h := f.n.holders.lookup(id, time.Now())
		if h == nil {
			t.Fatal("receipt returned before holder joined")
		}
		pub := newHolderTestPublisher()
		f.n.holders.setPublisher(&roomPublication{pub})
		if err := f.n.holders.perform(ctx, h, true, time.Now()); err != nil {
			t.Fatal(err)
		}
		requireInboxPush(t, ctx, r, 1, request.Message)
		var ack community.InboxAckedV1
		if err := r.peer.Query(ctx, community.InboxAckV1{Auth: proof, IDs: [][]byte{receipt.DMID}}, &ack); err != nil || ack.Deleted != 1 {
			t.Fatal("final ack", err)
		}
		if f.n.holders.lookup(id, time.Now()) != nil || h.ctx.Err() == nil {
			t.Fatal("empty holder membership retained")
		}
		if err := f.n.holders.perform(ctx, h, true, time.Now()); !errors.Is(err, context.Canceled) || pub.count() != 1 {
			t.Fatal("empty inbox kept publishing", err)
		}
		page := pushPage(t, ctx, r.peer, proof, 1, 100)
		if len(page.Messages) != 0 || page.LastSeqno != 1 {
			t.Fatal("empty authenticated page ceased to succeed")
		}
		request.Tier = 99
		pushDeposit(t, ctx, p, request)
		if f.n.holders.lookup(id, time.Now()) != nil {
			t.Fatal("deleted duplicate/tombstone invented membership")
		}
		rejected := inboxDeposit(t, sender, recipient, 2, time.Now().Unix()+300)
		rejected.Tier = 1
		var refusal community.InboxRejectedV1
		if err := p.Query(ctx, rejected, &refusal); err != nil || refusal.Code != 17 || f.n.holders.lookup(id, time.Now()) != nil {
			t.Fatal("rejected deposit joined", err)
		}
		next := inboxDeposit(t, sender, recipient, 3, time.Now().Unix()+300)
		pushDeposit(t, ctx, p, next)
		requireInboxPush(t, ctx, r, 2, next.Message) // Empty membership never removed the subscription.
		live := f.n.holders.lookup(id, time.Now())
		if f.n.holders.lookup(id, time.Unix(next.Message.ExpireAt, 0)) != nil {
			t.Fatal("expired envelope still served a holder selector")
		}
		if err := f.n.holders.perform(ctx, live, true, time.Now()); !errors.Is(err, context.Canceled) || pub.count() != 1 {
			t.Fatal("expired inbox kept publishing", err)
		}
		if err := f.n.holders.restore(ctx, time.Unix(next.Message.ExpireAt, 0)); err != nil || f.n.holders.lookup(id, time.Now()) != nil {
			t.Fatal("expired receipt restored holder membership", err)
		}
	}
}

func TestHoldersRestoreAllLiveInboxesAboveNewCapacityAndRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, false)
	sender := integrationKey(t)
	p := inboxPeer(t, ctx, f.n, sender)
	for i := 0; i < 3; i++ {
		pushDeposit(t, ctx, p, inboxDeposit(t, sender, integrationKey(t), byte(i+1), time.Now().Unix()+600))
	}
	if err := f.n.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := f.n.cfg
	cfg.Store = db
	cfg.Listen = integrationAddress(t)
	dm := *cfg.DM
	dm.Limits.MaxMessages = 1
	cfg.DM = &dm
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if len(n.holders.byInbox) != 3 {
		t.Fatal("restart stranded previously accepted inboxes behind new limits")
	}
	pub := newHolderTestPublisher()
	n.holders.setPublisher(&roomPublication{pub})
	now := time.Now()
	for i := 0; i < 3; i++ {
		n.holders.dispatch(now)
		select {
		case h := <-n.holders.publishJobs:
			if err := n.holders.perform(ctx, h, true, now); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("bounded queue stranded a live inbox")
		}
	}
	if pub.count() != 3 {
		t.Fatal("not all restored holders published")
	}
	var chosen *inboxHolder
	for _, h := range n.holders.byInbox {
		chosen = h
		break
	}
	if !chosen.nextPublish.Equal(now.Add(holderPublishEach)) {
		t.Fatal("wrong 90-second refresh cadence")
	}
	n.holders.dispatch(now.Add(89 * time.Second))
	if len(n.holders.publishJobs) != 0 {
		t.Fatal("holder republished before 90 seconds")
	}
	n.holders.dispatch(now.Add(90 * time.Second))
	h := <-n.holders.publishJobs
	pub.mu.Lock()
	pub.fail = true
	pub.mu.Unlock()
	if err := n.holders.perform(ctx, h, true, now.Add(90*time.Second)); err == nil || !h.nextPublish.Equal(now.Add(110*time.Second)) {
		t.Fatal("failed publish did not use bounded retry", err)
	}
	pub.mu.Lock()
	pub.fail = false
	pub.mu.Unlock()
	if err := n.holders.perform(ctx, h, true, now.Add(110*time.Second)); err != nil {
		t.Fatal(err)
	}
	key, _ := ov.InboxKey([]byte(h.inbox))
	pub.mu.Lock()
	last := pub.writes[len(pub.writes)-1]
	pub.mu.Unlock()
	if !bytes.Equal(last.key, key) || !last.at.Equal(now.Add(110*time.Second)) {
		t.Fatal("publisher received hashed selector instead of raw namespace")
	}
	roomOnly, _ := catalogFixture(t, true)
	if roomOnly.holders != nil {
		t.Fatal("room-only node started holder service")
	}
}

func TestHolderGossipFindsHolderOmittedFromDHTWithoutGrantingAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	a, b, c := freeInboxNode(t, 30*time.Second, true), freeInboxNode(t, 30*time.Second, true), freeInboxNode(t, 30*time.Second, false)
	sender, recipient := integrationKey(t), integrationKey(t)
	inbox := inboxID(t, recipient)
	id, _ := ov.InboxID(inbox)
	key, _ := ov.InboxKey(inbox)
	for _, f := range []*inboxNodeFixture{a, b, c} {
		p := inboxPeer(t, ctx, f.n, sender)
		pushDeposit(t, ctx, p, inboxDeposit(t, sender, recipient, 1, time.Now().Unix()+300))
	}
	hb := b.n.holders.lookup(id, time.Now())
	seedB := newHolderTestPublisher()
	seedB.endpoint(c.n)
	seedB.seeds[string(key)] = []tonoverlay.Node{signedRoomNode(t, c.n.cfg.Key, id, time.Now())}
	b.n.holders.setPublisher(&roomPublication{seedB})
	if err := b.n.holders.perform(ctx, hb, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	ha := a.n.holders.lookup(id, time.Now())
	seedA := newHolderTestPublisher()
	seedA.endpoint(b.n)
	seedA.endpoint(c.n)
	seedA.seeds[string(key)] = []tonoverlay.Node{signedRoomNode(t, b.n.cfg.Key, id, time.Now())} // C is deliberately omitted.
	a.n.holders.setPublisher(&roomPublication{seedA})
	valid := seedA.seeds[string(key)][0]
	bad := valid
	bad.Signature = bytes.Clone(valid.Signature)
	bad.Signature[0] ^= 1
	otherID, _ := ov.InboxID(inboxID(t, integrationKey(t)))
	for _, nd := range []tonoverlay.Node{bad, signedRoomNode(t, b.n.cfg.Key, otherID, time.Now()), signedRoomNode(t, b.n.cfg.Key, id, time.Now().Add(-601*time.Second)), signedRoomNode(t, b.n.cfg.Key, id, time.Now().Add(61*time.Second))} {
		ha.overlay.consider(ctx, nd)
	}
	if seedA.resolves.Load() != 0 {
		t.Fatal("forged/stale/cross-inbox hint reached DHT resolution")
	}
	if err := a.n.holders.perform(ctx, ha, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	ha.overlay.mu.Lock()
	count := len(ha.overlay.peers)
	ha.overlay.mu.Unlock()
	if count != 2 || seedA.resolves.Load() != 2 {
		t.Fatal("omitted holder not found through wrapped peer exchange", count, seedA.resolves.Load())
	}
	for _, f := range []*inboxNodeFixture{a, b} {
		if status := f.n.Status().Rooms[0]; status.Members != 0 || status.Neighbours != 0 {
			t.Fatal("holder gossip granted room association")
		}
	}
	p, _ := a.n.peers.get(outboundTestID(b.n.cfg.Key.Public().(ed25519.PublicKey)))
	proof := community.InboxAuthV1{RecipientKey: recipient.Public().(ed25519.PublicKey), Nonce: community.Zero256(), Signature: make([]byte, 64)}
	var pageRefused community.InboxPageRejectedV1
	if err := p.queryNode(ctx, community.GetInboxV1{Auth: proof}, &pageRefused); err != nil || pageRefused.Code != 18 {
		t.Fatal("holder exchange granted inbox read authority", err)
	}
	var ackRefused community.InboxAckRejectedV1
	if err := p.queryNode(ctx, community.InboxAckV1{Auth: proof}, &ackRefused); err != nil || ackRefused.Code != 18 {
		t.Fatal("holder exchange granted inbox delete authority", err)
	}
	list := ha.overlay.nodes(time.Now())
	if len(list.List) != 3 || len(list.List) > 8 {
		t.Fatal("holder gossip bound/self missing")
	}
	for _, nd := range list.List {
		if _, _, err := verifyOverlayNode(&nd, id, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	for len(ha.overlay.advertised) > 0 {
		<-ha.overlay.advertised
	}
	var hints []tonoverlay.Node
	for range maxGossipNodes + 1 {
		hints = append(hints, signedRoomNode(t, integrationKey(t), id, time.Now()))
	}
	ha.overlay.queue(hints)
	if len(ha.overlay.advertised) != maxGossipNodes {
		t.Fatal("holder hint queue/consideration bound changed")
	}
	raw, _ := community.Encode(tonoverlay.GetRandomPeers{})
	client := inboxPeer(t, ctx, a.n, integrationKey(t))
	for _, tc := range []struct {
		id         []byte
		tier, code int32
	}{{otherID, 1, 19}, {id, 1, 1}} {
		var refusal community.OverlayRejectedV1
		if err := client.Query(ctx, community.OverlayQueryV1{Overlay: tc.id, Tier: tc.tier, Query: raw}, &refusal); err != nil || refusal.Code != tc.code {
			t.Fatal("holder selector/tier rejection order", refusal, err)
		}
	}
	var peers tonoverlay.NodesList
	if err := client.QueryOverlay(ctx, id, tonoverlay.GetRandomPeers{}, &peers); err != nil {
		t.Fatal("live holder selector", err)
	}
	var wrong any
	if err := client.QueryOverlay(ctx, id, community.GetInboxV1{Auth: proof}, &wrong); err == nil {
		t.Fatal("inbox read was accepted inside peer-exchange selector")
	}
}

func TestHolderWorkersRefreshWhileDiscoveryBlocksAndJoinBeforeOwnerClose(t *testing.T) {
	for _, combined := range []bool{false, true} {
		t.Run(map[bool]string{false: "zero rooms", true: "combined"}[combined], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			n := freeInboxNode(t, 30*time.Second, combined).n
			sender, recipient := integrationKey(t), integrationKey(t)
			p := inboxPeer(t, ctx, n, sender)
			pushDeposit(t, ctx, p, inboxDeposit(t, sender, recipient, 1, time.Now().Unix()+300))
			inbox := inboxID(t, recipient)
			id, _ := ov.InboxID(inbox)
			key, _ := ov.InboxKey(inbox)
			h := n.holders.lookup(id, time.Now())
			pub := newHolderTestPublisher()
			pub.blockResolve = true
			pub.seeds[string(key)] = []tonoverlay.Node{signedRoomNode(t, integrationKey(t), id, time.Now())}
			n.cfg.LocalOnly, n.cfg.Advertise = false, "1.1.1.1:17400"
			var rooms []roomPublisher
			all := []*fakeRoomPublisher{&pub.fakeRoomPublisher}
			for _, r := range n.roomList() {
				p := &fakeRoomPublisher{room: r.genesis.RoomKey, started: make(chan struct{}), stopped: make(chan struct{})}
				rooms = append(rooms, p)
				all = append(all, p)
			}
			globals := map[string]roomPublisher{ov.Relays: pub}
			if n.catalog != nil {
				p := &fakeRoomPublisher{room: []byte(ov.PublicRooms), started: make(chan struct{}), stopped: make(chan struct{})}
				globals[ov.PublicRooms] = p
				all = append(all, p)
			}
			closed := false
			n.newPublishers = func(context.Context) ([]roomPublisher, map[string]roomPublisher, func(), error) {
				return rooms, globals, func() {
					for _, p := range all {
						select {
						case <-p.stopped:
						default:
							t.Error("DHT borrower still running")
						}
					}
					n.holders.mu.Lock()
					borrowed := n.holders.pub
					n.holders.mu.Unlock()
					if borrowed != nil {
						t.Error("holder publisher outlived workers")
					}
					pub.ownerClosed.Store(true)
					closed = true
				}, nil
			}
			stop := runPublicNode(t, ctx, n, all)
			select {
			case <-pub.blocked:
			case <-ctx.Done():
				t.Fatal("holder discovery never reached fake resolver", ctx.Err())
			}
			for pub.count() == 0 {
				select {
				case <-ctx.Done():
					t.Fatal("blocked discovery blocked own publication", ctx.Err())
				case <-time.After(time.Millisecond):
				}
			}
			n.holders.mu.Lock()
			h.nextPublish = time.Now().Add(-time.Second)
			n.holders.mu.Unlock()
			n.holders.signal()
			for pub.count() < 2 {
				select {
				case <-ctx.Done():
					t.Fatal("blocked discovery blocked refresh scheduler", ctx.Err())
				case <-time.After(time.Millisecond):
				}
			}
			if err := stop(); !errors.Is(err, context.Canceled) || !closed || pub.late.Load() {
				t.Fatal("holder work outlived shared DHT owner", err)
			}
			if _, err := n.database.LiveInboxes(ctx, time.Now()); err != nil {
				t.Fatal("holder shutdown closed borrowed Store", err)
			}
		})
	}
}
