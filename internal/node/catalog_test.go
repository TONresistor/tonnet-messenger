package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
)

func catalogFixture(t *testing.T, single bool) (*Node, *roomBindingFixture) {
	t.Helper()
	f := sharedRoomBinding(t)
	cfg := multiConfig(t, f)
	if single {
		cfg.Rooms = cfg.Rooms[:1]
	}
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n, f
}

func testCard(t *testing.T, key ed25519.PrivateKey, node []byte, version time.Time, alias string) community.RoomCardV1 {
	t.Helper()
	card, err := community.SignRoomCardV1(key, community.RoomCardV1{RoomKey: key.Public().(ed25519.PublicKey), NodeKey: node, Name: "Advertised", Alias: alias, Version: int32(version.Unix())})
	if err != nil {
		t.Fatal(err)
	}
	return card
}

func TestCatalogOwnCardsRefreshMetadataAndNeverSignReplica(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	n, f := catalogFixture(t, false)
	cards := n.catalog.list(256, now).Cards
	if len(cards) != 2 {
		t.Fatal("missing owned cards")
	}
	for _, card := range cards {
		if card.Verify() != nil || card.Alias != "" || !bytes.Equal(card.NodeKey, f.node.Public().(ed25519.PublicKey)) {
			t.Fatal("invalid own card")
		}
	}
	proposal := multiProposal(t, f.rooms[0].genesis, f.rooms[0].key, 0, community.EventMetadata{Name: "Updated", Description: "Current state"})
	if _, err := n.commitProposal(ctx, proposal, now); err != nil {
		t.Fatal(err)
	}
	if err := n.catalog.refreshOwn(ctx, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	updated := n.catalog.own[string(f.rooms[0].genesis.RoomKey)]
	if updated.Name != "Updated" || updated.Description != "Current state" || updated.Version != int32(now.Add(5*time.Minute).Unix()) || updated.Verify() != nil {
		t.Fatal("own card did not refresh from signed current state")
	}
	before := bindingRawState(t, f, 1)
	cfg := multiConfig(t, f)
	cfg.Rooms[1].RoomKey = nil
	cfg.Rooms[1].NodeRole = community.NodeRoleRelay
	mixed, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer mixed.Close()
	if len(mixed.catalog.list(256, time.Now()).Cards) != 1 || !bytes.Equal(before, bindingRawState(t, f, 1)) {
		t.Fatal("replica room acquired a signed card or state")
	}
	if len(n.catalog.list(256, now.Add(16*time.Minute)).Cards) != 0 {
		t.Fatal("expired own cards were served")
	}
}

func TestCatalogCardVerificationReplacementExpiryAndAliasHints(t *testing.T) {
	n, _ := catalogFixture(t, true)
	c, ctx, now := n.catalog, context.Background(), time.Now()
	key := integrationKey(t)
	card := testCard(t, key, n.cfg.Key.Public().(ed25519.PublicKey), now, "")
	if !c.accept(ctx, card, now) {
		t.Fatal("valid card rejected")
	}
	for _, version := range []time.Time{now.Add(-time.Second), now} {
		other := testCard(t, key, card.NodeKey, version, "")
		other.Name = "Equal or older"
		other, _ = community.SignRoomCardV1(key, other)
		if c.accept(ctx, other, now) {
			t.Fatal("non-increasing card replaced current version")
		}
	}
	newer := testCard(t, key, card.NodeKey, now.Add(time.Second), "")
	if !c.accept(ctx, newer, now) {
		t.Fatal("higher version did not replace card")
	}
	for _, offset := range []int{-601, -600, 60, 61} {
		candidate := testCard(t, integrationKey(t), card.NodeKey, now.Add(time.Duration(offset)*time.Second), "")
		if c.accept(ctx, candidate, now) != (offset >= -600 && offset <= 60) {
			t.Fatalf("freshness boundary %d", offset)
		}
	}
	for _, failure := range []string{"signature", "empty name", "oversized name", "invalid UTF8", "description", "control"} {
		bad := testCard(t, integrationKey(t), card.NodeKey, now, "")
		private := integrationKey(t)
		switch failure {
		case "signature":
			bad.Signature[0] ^= 1
		case "empty name":
			bad.Name = ""
		case "oversized name":
			bad.Name = strings.Repeat("x", 65)
		case "invalid UTF8":
			bad.Name = string([]byte{255})
		case "description":
			bad.Description = strings.Repeat("x", 513)
		case "control":
			bad.Name = "bad\nname"
		}
		if failure != "signature" {
			bad.RoomKey = private.Public().(ed25519.PublicKey)
			bad, _ = community.SignRoomCardV1(private, bad)
		}
		if c.accept(ctx, bad, now) {
			t.Fatalf("accepted invalid %s", failure)
		}
	}
	for _, alias := range []string{"verified.ton", "wrong.ton", "offline.ton", "not a domain"} {
		private := integrationKey(t)
		candidate := testCard(t, private, card.NodeKey, now, alias)
		n.resolveRoomAlias = func(_ context.Context, value string) ([]byte, error) {
			if value == "verified.ton" {
				return candidate.RoomKey, nil
			}
			if value == "wrong.ton" {
				return card.RoomKey, nil
			}
			return nil, errors.New("DNS unavailable")
		}
		raw, _ := community.Encode(candidate)
		if !c.accept(ctx, candidate, now) {
			t.Fatal("unverified alias invalidated otherwise valid card")
		}
		entry := c.cards[string(candidate.RoomKey)]
		if (entry.aliasHint != "") != (alias == "verified.ton") {
			t.Fatal("unverified alias became a trusted hint")
		}
		stored, _ := community.Encode(entry.card)
		if !bytes.Equal(raw, stored) || entry.card.Verify() != nil {
			t.Fatal("alias verification rewrote signed bytes")
		}
	}
	if len(c.list(256, now.Add(662*time.Second)).Cards) != 0 || len(c.cards) != 0 || c.bytes != 0 {
		t.Fatal("stale card cache did not expire")
	}
}

func TestCatalogBareLimitsCacheBoundsAndNoRoomMembership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n, _ := catalogFixture(t, true)
	now := time.Now()
	for i := 0; i <= maxCatalogCards; i++ {
		if !n.catalog.accept(ctx, testCard(t, integrationKey(t), n.cfg.Key.Public().(ed25519.PublicKey), now, ""), now) {
			t.Fatal("valid bounded advertisement rejected")
		}
	}
	if len(n.catalog.cards) != maxCatalogCards || n.catalog.bytes > maxCatalogBytes {
		t.Fatal("advertisement count bound failed")
	}
	remote := openMultiClient(t, ctx, n, integrationKey(t))
	for _, limit := range []int32{0, 1, 256} {
		var result community.RoomCardListV1
		if err := remote.peer.Query(ctx, community.GetRoomCardsV1{Limit: limit}, &result); err != nil {
			t.Fatal(err)
		}
		want := int(limit)
		if limit == 0 {
			want = 100
		}
		if len(result.Cards) != want {
			t.Fatalf("card page %d = %d", limit, len(result.Cards))
		}
		for _, card := range result.Cards {
			if card.Verify() != nil || !freshCard(card.Version, now) {
				t.Fatal("unverified card served")
			}
		}
	}
	for _, limit := range []int32{-1, 257} {
		var result community.SubmitRejected
		if err := remote.peer.Query(ctx, community.GetRoomCardsV1{Limit: limit}, &result); err != nil || result.Code != community.RejectMalformedRequest {
			t.Fatal("invalid page limit accepted", err)
		}
	}
	if status := n.Status().Rooms[0]; status.Members != 0 || status.Neighbours != 0 {
		t.Fatal("card queries joined a room")
	}
	for range 2 {
		key := integrationKey(t)
		large := testCard(t, key, n.cfg.Key.Public().(ed25519.PublicKey), now, strings.Repeat("x", maxCatalogBytes/2))
		if !n.catalog.accept(ctx, large, now) || n.catalog.bytes > maxCatalogBytes {
			t.Fatal("advertisement byte budget failed")
		}
	}
	answer := n.catalog.list(256, now)
	raw, err := community.Encode(answer)
	if err != nil || len(raw) > roomnet.MaxAnswerPayloadSize {
		t.Fatal("card answer exceeded transport bound")
	}
}

func TestCatalogExchangeDoesNotAuthorizeSingleRoomForwarding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, fa := catalogFixture(t, true)
	b, fb := catalogFixture(t, true)
	for _, pair := range [][2]*Node{{a, b}, {b, a}} {
		self, err := pair[1].signedOverlayNode(pair[0].catalog.id)
		if err != nil {
			t.Fatal(err)
		}
		fake := &fakeRoomPublisher{room: []byte(ov.PublicRooms), nodes: []tonoverlay.Node{self}, address: pair[1].cfg.Listen, public: pair[1].cfg.Key.Public().(ed25519.PublicKey)}
		pair[0].catalog.pub.Store(&roomPublication{fake})
		bad := self
		bad.Signature = bytes.Clone(self.Signature)
		bad.Signature[0] ^= 1
		stale := signedRoomNode(t, pair[1].cfg.Key, pair[0].catalog.id, time.Now().Add(-11*time.Minute))
		wrong := signedRoomNode(t, pair[1].cfg.Key, pair[0].room.overlayID, time.Now())
		for _, invalid := range []tonoverlay.Node{bad, stale, wrong} {
			pair[0].catalog.consider(ctx, invalid)
		}
		if fake.resolves.Load() != 0 {
			t.Fatal("invalid global advertisement reached address resolution")
		}
		pair[0].catalog.discover(ctx)
		if fake.finds.Load() != 1 || fake.resolves.Load() != 1 {
			t.Fatal("catalog did not use the global DHT seed once")
		}
	}
	for _, n := range []*Node{a, b} {
		if status := n.Status().Rooms[0]; status.Neighbours != 0 || status.Members != 0 {
			t.Fatalf("global membership granted room authority: %+v", status)
		}
		cards := n.catalog.list(256, time.Now()).Cards
		if len(cards) != 2 {
			t.Fatal("signed room-card exchange failed")
		}
		for _, card := range cards {
			if card.Verify() != nil {
				t.Fatal("invalid pulled card")
			}
		}
	}
	// The reverse catalog connection must not trigger the old single-room
	// inbound shortcut, and the shared peer must keep strict outbound I/O.
	p, ok := b.peers.get(outboundTestID(fa.node.Public().(ed25519.PublicKey)))
	if !ok || !b.outboundReady(p) {
		t.Fatal("compatible shared peer missing")
	}
	proposal := multiProposal(t, fa.rooms[0].genesis, integrationKey(t), 0, community.EventMessage{Text: "forged forwarding"})
	var rejected community.SubmitRejected
	if err := p.queryNodeRoom(ctx, fa.rooms[0].genesis.RoomKey, community.SubmitEvent{Proposal: proposal}, &rejected); err != nil || rejected.Code != community.RejectPermissionDenied {
		t.Fatalf("global peer forwarded another identity: %+v %v", rejected, err)
	}
	if head, err := fa.rooms[0].view.Head(ctx); err != nil || head.Seqno != 0 {
		t.Fatal("global membership changed room history")
	}
	// An explicit scoped query for a room the peer does not serve remains 19.
	var peers tonoverlay.NodesList
	if err := p.queryNodeRoom(ctx, fb.rooms[0].genesis.RoomKey, tonoverlay.GetRandomPeers{}, &peers); err == nil {
		t.Fatal("global membership invented room service")
	}
	a.catalog.mu.Lock()
	aCount := len(a.catalog.peers)
	a.catalog.mu.Unlock()
	b.catalog.mu.Lock()
	bCount := len(b.catalog.peers)
	b.catalog.mu.Unlock()
	if aCount != 1 || bCount != 1 {
		t.Fatal("room rejection damaged global membership")
	}
}

func TestCatalogOnlySequencersPublishAndLifecycleClosesBorrowers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n, _ := catalogFixture(t, true)
	n.cfg.LocalOnly = false
	n.cfg.Advertise = "1.1.1.1:17400"
	// Simulate a delayed Run, with a correctly signed but expired own card.
	for key, card := range n.catalog.own {
		card.Version -= 601
		card, err := community.SignRoomCardV1(n.room.roomKey, card)
		if err != nil {
			t.Fatal(err)
		}
		n.catalog.own[key] = card
	}
	roomPub := &fakeRoomPublisher{room: n.room.genesis.RoomKey, started: make(chan struct{}), stopped: make(chan struct{})}
	global := &fakeRoomPublisher{room: []byte(ov.PublicRooms), started: make(chan struct{}), stopped: make(chan struct{}), resolveEntered: make(chan struct{})}
	closed := false
	n.newPublishers = func(context.Context) ([]roomPublisher, map[string]roomPublisher, func(), error) {
		return []roomPublisher{roomPub}, map[string]roomPublisher{ov.PublicRooms: global}, func() {
			select {
			case <-global.stopped:
			default:
				t.Error("global DHT borrower still running")
			}
			closed = true
		}, nil
	}
	stop := runPublicNode(t, ctx, n, []*fakeRoomPublisher{roomPub, global})
	self, err := n.signedOverlayNode(n.catalog.id)
	if err != nil || self.CheckSignature() != nil {
		t.Fatal(err)
	}
	// A verified foreign hint blocks in fake resolution until Run cancellation.
	nd := signedRoomNode(t, integrationKey(t), n.catalog.id, time.Now())
	n.catalog.queue([]tonoverlay.Node{nd})
	select {
	case <-global.resolveEntered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if cards := n.catalog.list(256, time.Now()).Cards; len(cards) != 1 || cards[0].Verify() != nil {
		t.Fatal("delayed startup did not refresh own cards")
	}
	if err := stop(); !errors.Is(err, context.Canceled) || !closed || n.catalog.pub.Load() != nil {
		t.Fatalf("catalog lifecycle: %v", err)
	}
	// A replica-only node has no public-rooms membership and signs no cards.
	f := sharedRoomBinding(t)
	cfg := bindingConfig(t, f, 0)
	cfg.Key = integrationKey(t)
	cfg.RoomKey = nil
	cfg.NodeRole = community.NodeRoleRelay
	cfg.LocalOnly = true
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.catalog != nil {
		t.Fatal("replica joined public-rooms overlay")
	}
	remote := openMultiClient(t, ctx, r, integrationKey(t))
	var result community.RoomCardListV1
	if err := remote.peer.Query(ctx, community.GetRoomCardsV1{}, &result); err != nil || len(result.Cards) != 0 {
		t.Fatal("replica signed room cards", err)
	}
}
