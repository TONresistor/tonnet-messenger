package node

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"
)

func TestRelayIdleBoundaries(t *testing.T) {
	base := time.Unix(1700000000, 0)
	for _, tc := range []struct {
		name               string
		elapsed            time.Duration
		member, subscribed bool
		expiry             time.Duration
		inFlight           int
		want               bool
	}{
		{"ordinary before 30", 30*time.Second - time.Nanosecond, false, false, 0, 0, false},
		{"ordinary at 30", 30 * time.Second, false, false, 0, 0, true},
		{"member before 150", 150*time.Second - time.Nanosecond, true, false, 0, 0, false},
		{"member at 150", 150 * time.Second, true, false, 0, 0, true},
		{"subscriber before 150", 150*time.Second - time.Nanosecond, false, true, 300 * time.Second, 0, false},
		{"subscriber at 150", 150 * time.Second, false, true, 300 * time.Second, 0, true},
		{"expired subscription", 30 * time.Second, false, true, 30 * time.Second, 0, true},
		{"request in flight", time.Hour, false, false, 0, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := inboxConnection{lastActivity: base, inFlight: tc.inFlight}
			if tc.subscribed {
				state.subscription = &inboxSubscription{expireAt: base.Add(tc.expiry).Unix()}
			}
			if got := state.idleAt(base.Add(tc.elapsed), tc.member); got != tc.want {
				t.Fatalf("idle=%v, want %v", got, tc.want)
			}
		})
	}
	state := inboxConnection{lastActivity: base.Add(20 * time.Second)}
	if state.idleAt(base.Add(49*time.Second), false) || !state.idleAt(base.Add(50*time.Second), false) {
		t.Fatal("activity did not move the ordinary deadline")
	}
}

func waitIdleConnection(t *testing.T, ctx context.Context, n *Node, key ed25519.PrivateKey, exclude *quic.Client) (*quic.Client, inboxConnection) {
	t.Helper()
	for {
		n.inbox.mu.Lock()
		for conn, state := range n.inbox.connections {
			if conn != exclude && conn.Context().Err() == nil && conn.PeerKey().Equal(key.Public()) {
				copy := *state
				n.inbox.mu.Unlock()
				return conn, copy
			}
		}
		n.inbox.mu.Unlock()
		select {
		case <-ctx.Done():
			t.Fatal("missing physical opening", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

func waitIdleCompletion(t *testing.T, ctx context.Context, n *Node, conn *quic.Client, answeredAfter time.Time) inboxConnection {
	t.Helper()
	for {
		n.inbox.mu.Lock()
		state := n.inbox.connections[conn]
		if state != nil && state.inFlight == 0 && (answeredAfter.IsZero() || state.lastActivity.After(answeredAfter)) {
			copy := *state
			n.inbox.mu.Unlock()
			return copy
		}
		n.inbox.mu.Unlock()
		select {
		case <-ctx.Done():
			t.Fatal("query lifetime did not complete", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

func ageIdleConnection(n *Node, conn *quic.Client, at time.Time) {
	n.inbox.mu.Lock()
	n.inbox.connections[conn].lastActivity = at
	n.inbox.mu.Unlock()
}

func TestRelayIdleSilentOpeningAndSameKeyReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, false)
	key := integrationKey(t)
	inboxPeer(t, ctx, f.n, key) // No query or challenge.
	old, first := waitIdleConnection(t, ctx, f.n, key, nil)
	before := time.Now()
	inboxPeer(t, ctx, f.n, key)
	next, opened := waitIdleConnection(t, ctx, f.n, key, old)
	if opened.lastActivity.Before(before) || opened.subscription != nil || opened.inFlight != 0 || len(opened.challenges) != 0 {
		t.Fatal("silent replacement inherited activity/authentication")
	}
	f.n.evictIdlePeers(first.lastActivity.Add(30 * time.Second))
	if next.Context().Err() != nil {
		t.Fatal("old opening deadline closed newer physical connection")
	}
	f.n.evictIdlePeers(opened.lastActivity.Add(30 * time.Second))
	if next.Context().Err() == nil {
		t.Fatal("silent connection survived its own deadline")
	}
}

func TestRelayIdleAnsweredQueriesAndCombinedRoomMembership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, true)
	key, recipient := integrationKey(t), integrationKey(t)
	p := inboxPeer(t, ctx, f.n, key)
	conn, opened := waitIdleConnection(t, ctx, f.n, key, nil)
	base := opened.lastActivity.Add(-time.Hour)
	// A recent DM/capability answer must survive the old firstSeen eviction.
	f.n.peers.mu.Lock()
	opened.peer.firstSeen = base
	f.n.peers.mu.Unlock()
	f.n.queries = newTokenBucket(0, 0)
	ageIdleConnection(f.n, conn, base)
	var caps community.Capabilities
	if err := p.Query(ctx, community.GetCapabilities{}, &caps); err != nil || caps.Flags != community.RelayServiceDM {
		t.Fatal("capability under exhausted limit", err)
	}
	state := waitIdleCompletion(t, ctx, f.n, conn, base)
	f.n.evictIdlePeers(state.lastActivity.Add(29 * time.Second))
	if conn.Context().Err() != nil {
		t.Fatal("answered capability did not refresh idle deadline")
	}
	f.n.queries = newTokenBucket(globalQueryBurst, globalQueryRefill)
	request := inboxDeposit(t, key, recipient, 1, time.Now().Unix()+300)
	request.Tier = 1
	for _, tc := range []struct {
		name              string
		request, response any
	}{
		{"time", broadcast.GetTime{}, &broadcast.Time{}},
		{"typed rejection", request, &community.InboxRejectedV1{}},
		{"cards", community.GetRoomCardsV1{Limit: 1}, &community.RoomCardListV1{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ageIdleConnection(f.n, conn, base)
			if err := p.Query(ctx, tc.request, tc.response); err != nil {
				t.Fatal(err)
			}
			waitIdleCompletion(t, ctx, f.n, conn, base)
		})
	}
	ageIdleConnection(f.n, conn, base)
	var unknown any
	if err := p.Query(ctx, broadcast.Time{}, &unknown); err == nil {
		t.Fatal("unsupported query unexpectedly answered")
	}
	if state := waitIdleCompletion(t, ctx, f.n, conn, time.Time{}); !state.lastActivity.Equal(base) {
		t.Fatal("unanswered/reset query counted as activity")
	}
	var genesis community.Genesis
	if err := p.QueryRoom(ctx, f.room.RoomKey, community.GetRoomGenesis{}, &genesis); err != nil {
		t.Fatal(err)
	}
	state = waitIdleCompletion(t, ctx, f.n, conn, base)
	f.n.evictIdlePeers(state.lastActivity.Add(149 * time.Second))
	if conn.Context().Err() != nil || !f.n.forRoom(f.n.room).peers.isMember(state.peer) {
		t.Fatal("combined room member was evicted early")
	}
	f.n.evictIdlePeers(state.lastActivity.Add(150 * time.Second))
	if conn.Context().Err() == nil {
		t.Fatal("combined room member survived idle deadline")
	}
}

func TestRelayIdleKeepsRequestThroughAnswerWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, false)
	key := integrationKey(t)
	p := inboxPeer(t, ctx, f.n, key)
	conn, state := waitIdleConnection(t, ctx, f.n, key, nil)
	base := state.lastActivity.Add(-time.Hour)
	ageIdleConnection(f.n, conn, base)
	prepared, release := make(chan struct{}), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	state.peer.conn.SetQueryHandlerWithLifecycle(func(q *roomnet.Query) error { return f.n.answerQuery(state.peer, q) }, func(request context.Context) func(bool) {
		finish := f.n.inbox.beginQuery(request)
		return func(answered bool) {
			finish(answered)
			close(prepared)
			select {
			case <-release:
			case <-request.Done():
			}
		}
	})
	done := make(chan error, 1)
	go func() { var clock broadcast.Time; done <- p.Query(ctx, broadcast.GetTime{}, &clock) }()
	select {
	case <-prepared:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	f.n.evictIdlePeers(base.Add(2 * time.Hour))
	if conn.Context().Err() != nil {
		t.Fatal("idle sweep closed an in-flight response")
	}
	f.n.inbox.mu.Lock()
	active := f.n.inbox.connections[conn].inFlight
	f.n.inbox.mu.Unlock()
	if active != 1 {
		t.Fatal("prepared answer ended request before stream completion")
	}
	close(release)
	released = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	waitIdleCompletion(t, ctx, f.n, conn, base)
}

func TestRelayIdlePushActivityAndDurableDataAfterClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, false)
	sender, recipient, transport := integrationKey(t), integrationKey(t), integrationKey(t)
	p := inboxPeer(t, ctx, f.n, sender)
	r := newInboxPushReceiver(t, ctx, f.n, transport)
	conn, opening := waitIdleConnection(t, ctx, f.n, transport, nil)
	proof := inboxAuth(t, f.n, recipient, challenge(t, ctx, r.peer, inboxID(t, recipient)))
	pushPage(t, ctx, r.peer, proof, 0, 100)
	waitIdleCompletion(t, ctx, f.n, conn, opening.lastActivity)
	base := time.Now().Add(-time.Hour)
	ageIdleConnection(f.n, conn, base)
	request := inboxDeposit(t, sender, recipient, 1, time.Now().Unix()+300)
	pushDeposit(t, ctx, p, request)
	requireInboxPush(t, ctx, r, 1, request.Message)
	state := waitIdleCompletion(t, ctx, f.n, conn, base)
	if state.subscription == nil {
		t.Fatal("missing subscription after push")
	}
	ageIdleConnection(f.n, conn, base)
	// An oversized message exercises send failure without closing/replacing
	// the physical connection or invoking another request.
	oversized := community.InboxPushV1{Message: community.DirectMessageV3{Ciphertext: make([]byte, roomnet.MaxWireObjectSize)}}
	f.n.writeInboxPush(outboundJob{physical: conn, subscription: state.subscription, items: []tl.Serializable{oversized}})
	if got := waitIdleCompletion(t, ctx, f.n, conn, time.Time{}); !got.lastActivity.Equal(base) {
		t.Fatal("failed push counted as activity")
	}
	f.n.evictIdlePeers(time.Unix(state.subscription.expireAt, 0))
	if conn.Context().Err() == nil {
		t.Fatal("expired subscription retained the 150-second allowance")
	}
	page, err := f.db.PageInbox(ctx, inboxID(t, recipient), 0, 100, time.Now())
	if err != nil || len(page.Page.Messages) != 1 {
		t.Fatal("idle close deleted durable deposit", err)
	}
}

func TestRelayIdleVerifiedNodeAndRoomOnlyPolicies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f := freeInboxNode(t, 30*time.Second, true)
	key := integrationKey(t)
	inboxPeer(t, ctx, f.n, key)
	conn, state := waitIdleConnection(t, ctx, f.n, key, nil)
	f.n.peers.mu.Lock()
	state.peer.kind, state.peer.state = kindNode, peerHealthy
	f.n.peers.mu.Unlock()
	f.n.evictIdlePeers(state.lastActivity.Add(time.Hour))
	if conn.Context().Err() != nil {
		t.Fatal("existing verified-node lifecycle changed")
	}
	f.n.peers.mu.Lock()
	state.peer.state = peerQuarantine
	f.n.peers.mu.Unlock()
	f.n.evictIdlePeers(state.lastActivity.Add(time.Hour))
	if conn.Context().Err() == nil {
		t.Fatal("unverified node classification invented an idle exemption")
	}
	base := time.Unix(1700000000, 0)
	roomOnly := &Node{peers: newPeerTable(1)}
	ordinary := newPeer("ordinary", kindLeaf, nil, nil)
	ordinary.firstSeen, ordinary.lastGood = base, base.Add(29*time.Second)
	member := newPeer("member", kindLeaf, nil, nil)
	member.firstSeen, member.lastGood, member.member = base, base, true
	roomOnly.peers.m[ordinary.id], roomOnly.peers.m[member.id] = ordinary, member
	roomOnly.evictIdlePeers(base.Add(31 * time.Second))
	if _, exists := roomOnly.peers.get(ordinary.id); exists {
		t.Fatal("room-only firstSeen policy changed")
	}
	if _, exists := roomOnly.peers.get(member.id); !exists {
		t.Fatal("room-only member lost its legacy allowance")
	}
	roomOnly.evictIdlePeers(base.Add(151 * time.Second))
	if _, exists := roomOnly.peers.get(member.id); exists {
		t.Fatal("room-only member no longer expires")
	}
}
