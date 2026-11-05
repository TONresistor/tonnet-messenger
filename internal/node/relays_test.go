package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/xssnick/tonutils-go/adnl/address"
	tonkeys "github.com/xssnick/tonutils-go/adnl/keys"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"
)

func TestRelayOwnCardMatchesServiceAndRefreshes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for _, combined := range []bool{false, true} {
		f := freeInboxNode(t, 30*time.Second, combined)
		p := inboxPeer(t, ctx, f.n, integrationKey(t))
		f.n.queries.mu.Lock()
		f.n.queries.tokens, f.n.queries.refillPerSec = 0, 0
		f.n.queries.mu.Unlock()
		var caps community.Capabilities
		if err := p.Query(ctx, community.GetCapabilities{}, &caps); err != nil || caps.Flags != community.RelayServiceDM {
			t.Fatal("truthful/exempt capabilities", caps, err)
		}
		f.n.queries.mu.Lock()
		f.n.queries.tokens, f.n.queries.refillPerSec = globalQueryBurst, globalQueryRefill
		f.n.queries.last = time.Now()
		f.n.queries.mu.Unlock()
		var card community.RelayCardV1
		if err := p.Query(ctx, community.GetRelayCardV1{}, &card); err != nil || card.Verify() != nil || !freshCard(card.Version, time.Now()) {
			t.Fatal("own card", err)
		}
		if !bytes.Equal(card.RelayKey, f.n.cfg.Key.Public().(ed25519.PublicKey)) || card.Services != 2 || !bytes.Equal(card.PaymentKey, community.Zero256()) || len(card.Offers) != 1 || card.Offers[0] != *f.n.cfg.DM.Limits.Offer {
			t.Fatal("card differs from admission configuration")
		}
		raw, err := tl.Serialize(card.Addrs, true)
		if err != nil || len(raw) > community.MaxRelayAddressBytes || len(card.Addrs.Addresses) != 1 || address.PortValue(card.Addrs.Addresses[0]) == 0 {
			t.Fatal("invalid QUIC address list", err)
		}
		switch card.Addrs.Addresses[0].(type) {
		case address.QUIC, *address.QUIC:
		default:
			t.Fatal("non-QUIC card endpoint")
		}
		when := time.Unix(int64(card.Version)+300, 0)
		if err := f.n.relays.refreshOwn(ctx, when); err != nil {
			t.Fatal(err)
		}
		fresh, err := f.n.relays.ownCard(when)
		if err != nil || fresh.Version != int32(when.Unix()) || fresh.Version <= card.Version || fresh.Verify() != nil {
			t.Fatal("five-minute refresh", err)
		}
		before, _ := community.Encode(fresh)
		fresh.Offers[0].MaxObjectBytes = 1
		fresh.Signature[0] ^= 1
		again, err := f.n.relays.ownCard(when)
		after, _ := community.Encode(again)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("caller mutated cached own card")
		}
		if combined {
			if s := f.n.Status().Rooms[0]; s.Members != 0 || s.Neighbours != 0 {
				t.Fatal("card/capability query joined a room")
			}
		}
	}
	roomOnly, f := catalogFixture(t, true)
	cfg := bindingConfig(t, f, 0)
	cfg.Key, cfg.RoomKey, cfg.NodeRole, cfg.LocalOnly = integrationKey(t), nil, community.NodeRoleRelay, true
	replica, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	for _, n := range []*Node{roomOnly, replica} {
		if n.relays != nil {
			t.Fatal("room-only runtime joined relays")
		}
		p := inboxPeer(t, ctx, n, integrationKey(t))
		var caps community.Capabilities
		if err := p.Query(ctx, community.GetCapabilities{}, &caps); err != nil || caps.Flags != 0 {
			t.Fatal("room-only DM flag", err)
		}
		var card community.RelayCardV1
		if err := p.Query(ctx, community.GetRelayCardV1{}, &card); err == nil {
			t.Fatal("disabled DM service signed a relay card")
		}
	}
}

func TestRelayDiscoveryCardsAndRoomAuthorityAreIndependent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	a, b := freeInboxNode(t, 30*time.Second, true), freeInboxNode(t, 30*time.Second, true)
	for _, pair := range [][2]*inboxNodeFixture{{a, b}, {b, a}} {
		local, remote := pair[0].n, pair[1].n
		nd := signedRoomNode(t, remote.cfg.Key, local.relays.id, time.Now())
		fake := &fakeRoomPublisher{room: []byte(ov.Relays), nodes: []tonoverlay.Node{nd}, address: remote.cfg.Listen, public: remote.cfg.Key.Public().(ed25519.PublicKey)}
		local.relays.pub.Store(&roomPublication{fake})
		bad := nd
		bad.Signature = bytes.Clone(nd.Signature)
		bad.Signature[0] ^= 1
		wrongKey := nd
		wrongKey.ID = tonkeys.PublicKeyED25519{Key: integrationKey(t).Public().(ed25519.PublicKey)}
		for _, invalid := range []tonoverlay.Node{bad, wrongKey, signedRoomNode(t, remote.cfg.Key, local.room.overlayID, time.Now()), signedRoomNode(t, remote.cfg.Key, local.relays.id, time.Now().Add(-601*time.Second)), signedRoomNode(t, remote.cfg.Key, local.relays.id, time.Now().Add(61*time.Second))} {
			local.relays.consider(ctx, invalid)
		}
		if fake.resolves.Load() != 0 {
			t.Fatal("invalid relay advertisement reached resolution")
		}
		local.relays.discover(ctx)
		if fake.finds.Load() != 1 || fake.resolves.Load() != 1 {
			t.Fatal("relay discovery did not use its DHT seed")
		}
		local.relays.mu.Lock()
		cards, peers := len(local.relays.cards), len(local.relays.peers)
		local.relays.mu.Unlock()
		if cards != 1 || peers != 1 {
			t.Fatal("relay card/peer not discovered", cards, peers)
		}
		if s := local.Status().Rooms[0]; s.Members != 0 || s.Neighbours != 0 {
			t.Fatal("global peer acquired room authority")
		}
	}
	p, _ := a.n.peers.get(outboundTestID(b.n.cfg.Key.Public().(ed25519.PublicKey)))
	var rejected community.SubmitRejected
	proposal := multiProposal(t, *b.room, integrationKey(t), 0, community.EventMessage{Text: "not a room replica"})
	if err := p.queryNodeRoom(ctx, b.room.RoomKey, community.SubmitEvent{Proposal: proposal}, &rejected); err != nil || rejected.Code != community.RejectPermissionDenied {
		t.Fatal("global discovery authorized forwarding", rejected, err)
	}
	r := a.n.relays
	base, err := b.n.relays.ownCard(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(int64(base.Version), 0)
	sign := func(card community.RelayCardV1) community.RelayCardV1 {
		t.Helper()
		c, err := community.SignRelayCardV1(b.n.cfg.Key, card)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	r.mu.Lock()
	r.dropCardLocked(p)
	r.mu.Unlock()
	if !r.accept(p, base, now) || r.accept(p, base, now) {
		t.Fatal("card first/equal version rule")
	}
	older := base
	older.Version--
	older = sign(older)
	if r.accept(p, older, now) {
		t.Fatal("older card replaced current")
	}
	newer := base
	newer.Version++
	newer = sign(newer)
	if !r.accept(p, newer, now) {
		t.Fatal("newer card not installed")
	}
	for _, offset := range []int32{-601, -600, 60, 61} {
		candidate := base
		candidate.Version += offset
		candidate = sign(candidate)
		r.mu.Lock()
		r.dropCardLocked(p)
		r.mu.Unlock()
		if r.accept(p, candidate, now) != (offset >= -600 && offset <= 60) {
			t.Fatal("card freshness boundary", offset)
		}
	}
	foreign, _ := community.SignRelayCardV1(a.n.cfg.Key, community.RelayCardV1{RelayKey: a.n.cfg.Key.Public().(ed25519.PublicKey), Addrs: base.Addrs, Services: 2, PaymentKey: community.Zero256(), Offers: base.Offers, Version: base.Version})
	badSignature := base
	badSignature.Signature = bytes.Clone(base.Signature)
	badSignature.Signature[0] ^= 1
	unknown := base
	unknown.Services |= 8
	unknown = sign(unknown)
	oversized := base
	oversized.Offers = append([]community.RelayOfferV1(nil), base.Offers...)
	oversized.Offers[0].MaxObjectBytes = community.MaxRelayObjectBytes + 1
	for _, bad := range []community.RelayCardV1{foreign, badSignature, unknown, oversized} {
		if r.accept(p, bad, now) {
			t.Fatal("invalid/mismatched relay card accepted")
		}
	}
	r.mu.Lock()
	r.dropCardLocked(p)
	r.bytes = maxCatalogBytes
	r.mu.Unlock()
	if r.accept(p, base, now) {
		t.Fatal("relay cards exceeded existing byte budget")
	}
	r.mu.Lock()
	r.bytes = 0
	// Represent a full byte budget without allocating multi-megabyte fixtures.
	victim := newPeer("cached advertisement", kindNode, nil, nil)
	r.cards[victim] = relayCardEntry{card: older, size: maxCatalogBytes}
	r.bytes = maxCatalogBytes
	r.mu.Unlock()
	if !r.accept(p, newer, now) {
		t.Fatal("higher card version did not evict an older advertisement")
	}
	r.mu.Lock()
	_, retained := r.cards[victim]
	size := r.bytes
	r.mu.Unlock()
	if retained || size > maxCatalogBytes {
		t.Fatal("relay card eviction exceeded byte budget")
	}
}

type relaySeedPublisher struct {
	fakeRoomPublisher
	addresses map[string]string
	keys      map[string]ed25519.PublicKey
}

func (p *relaySeedPublisher) ResolveAll(ctx context.Context, id []byte) ([]string, ed25519.PublicKey, error) {
	p.resolves.Add(1)
	return []string{p.addresses[string(id)]}, p.keys[string(id)], ctx.Err()
}

func TestRelaysGossipAndNeighbourBudgets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	local := freeInboxNode(t, 30*time.Second, false).n
	seed := &relaySeedPublisher{fakeRoomPublisher: fakeRoomPublisher{room: []byte(ov.Relays)}, addresses: make(map[string]string), keys: make(map[string]ed25519.PublicKey)}
	// One item beyond the protocol's 16 considered advertisements, using actual
	// authenticated localhost endpoints and the existing node budget.
	for range maxGossipNodes + 1 {
		remote := freeInboxNode(t, 30*time.Second, false).n
		nd := signedRoomNode(t, remote.cfg.Key, local.relays.id, time.Now())
		id, _ := community.KeyID(remote.cfg.Key.Public().(ed25519.PublicKey))
		seed.nodes = append(seed.nodes, nd)
		seed.addresses[string(id)] = remote.cfg.Listen
		seed.keys[string(id)] = remote.cfg.Key.Public().(ed25519.PublicKey)
	}
	local.relays.pub.Store(&roomPublication{seed})
	local.relays.discover(ctx)
	if seed.resolves.Load() != maxGossipNodes || len(local.relays.peers) != MaxNodePeers || len(local.relays.cards) != MaxNodePeers {
		t.Fatal("unbounded relay seed/peer/card state")
	}
	list := local.relays.nodes(time.Now())
	if len(list.List) != 8 || !list.List[0].ID.(tonkeys.PublicKeyED25519).Key.Equal(local.cfg.Key.Public()) {
		t.Fatal("gossip is not self plus seven")
	}
	for _, nd := range list.List {
		if _, _, err := verifyOverlayNode(&nd, local.relays.id, time.Now()); err != nil {
			t.Fatal("invalid relays gossip", err)
		}
	}
	if len(local.relays.advertised) > maxGossipNodes {
		t.Fatal("unbounded relay hint queue")
	}
	local.relays.mu.Lock()
	local.relays.pruneLocked(time.Now().Add(601 * time.Second))
	peers, cards := len(local.relays.peers), len(local.relays.cards)
	local.relays.mu.Unlock()
	if peers != 0 || cards != 0 {
		t.Fatal("expired relay neighbours/cards retained")
	}
}

func TestRelaysRoutingAndPublicLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, combined := range []bool{false, true} {
		f := freeInboxNode(t, 30*time.Second, combined)
		p := inboxPeer(t, ctx, f.n, integrationKey(t))
		raw, _ := community.Encode(tonoverlay.GetRandomPeers{})
		for _, tc := range []struct {
			id         []byte
			tier, code int32
		}{{community.Zero256(), 1, 19}, {f.n.relays.id, 1, 1}} {
			var rejected community.OverlayRejectedV1
			if err := p.Query(ctx, community.OverlayQueryV1{Overlay: tc.id, Tier: tc.tier, Query: raw}, &rejected); err != nil || rejected.Code != tc.code {
				t.Fatal("overlay rejection ordering", rejected, err)
			}
		}
		var peers tonoverlay.NodesList
		if err := p.QueryOverlay(ctx, f.n.relays.id, tonoverlay.GetRandomPeers{}, &peers); err != nil || len(peers.List) != 1 {
			t.Fatal("wrapped relays peers", err)
		}
		f.n.cfg.LocalOnly = false
		if err := f.n.Run(ctx); err == nil {
			t.Fatal("public DM Run accepted a missing advertise endpoint")
		}
		f.n.cfg.Advertise = "1.1.1.1:17400"
		roomPubs, closed, premature := fakePublicRooms(f.n)
		stop := runPublicNode(t, ctx, f.n, roomPubs)
		for _, global := range f.n.globalOverlays() {
			for global.pub.Load() == nil {
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(time.Millisecond):
				}
			}
			fake := global.pub.Load().roomPublisher.(*fakeRoomPublisher)
			select {
			case <-fake.started:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		if err := stop(); !errors.Is(err, context.Canceled) || closed.Load() != 1 || premature.Load() {
			t.Fatal("shared DHT owner closed before borrowers", err)
		}
		for _, global := range f.n.globalOverlays() {
			if global.pub.Load() != nil {
				t.Fatal("global publisher retained after Run")
			}
		}
	}
}

func TestRelaysDelayedStartupRefreshAndSeedSurviveBlockedNeighbour(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	n := freeInboxNode(t, 30*time.Second, false).n
	n.cfg.LocalOnly, n.cfg.Advertise = false, "1.1.1.1:17400"
	n.relays.mu.Lock()
	n.relays.own.Version -= 601
	n.relays.mu.Unlock()
	pub := &fakeRoomPublisher{room: []byte(ov.Relays), started: make(chan struct{}), stopped: make(chan struct{}), resolveEntered: make(chan struct{})}
	closed := false
	n.newPublishers = func(context.Context) ([]roomPublisher, map[string]roomPublisher, func(), error) {
		return nil, map[string]roomPublisher{ov.Relays: pub}, func() {
			select {
			case <-pub.stopped:
			default:
				t.Error("relays borrower still running")
			}
			closed = true
		}, nil
	}
	stop := runPublicNode(t, ctx, n, []*fakeRoomPublisher{pub})
	n.relays.queue([]tonoverlay.Node{signedRoomNode(t, integrationKey(t), n.relays.id, time.Now())})
	select {
	case <-pub.resolveEntered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	card, err := n.relays.ownCard(time.Now())
	if err != nil || card.Verify() != nil || !freshCard(card.Version, time.Now()) || !address.IPValue(card.Addrs.Addresses[0]).Equal([]byte{1, 1, 1, 1}) {
		t.Fatal("delayed startup served stale/wrong card", err)
	}
	for pub.finds.Load() == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("neighbour I/O blocked seed refresh", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	when := time.Now().Add(5 * time.Minute)
	if err := n.relays.refreshOwn(ctx, when); err != nil {
		t.Fatal(err)
	}
	fresh, err := n.relays.ownCard(when)
	if err != nil || fresh.Version <= card.Version {
		t.Fatal("neighbour I/O blocked own refresh", err)
	}
	if err := stop(); !errors.Is(err, context.Canceled) || !closed || n.relays.pub.Load() != nil {
		t.Fatal("blocked neighbour outlived DHT owner", err)
	}
}
