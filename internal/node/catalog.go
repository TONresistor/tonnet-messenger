package node

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/dht"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
)

const maxCatalogCards = 1024
const maxCatalogBytes = roomnet.MaxAnswerObjectSize

type catalogCard struct {
	card      community.RoomCardV1
	aliasHint string // Verified separately; never rewrite the signed Alias.
	size      int
}

// Global membership is independent of roomContext and its authorization maps.
// Remote advertisements have count/byte bounds; own cards are bounded by the
// operator's configured sequencer rooms and always take precedence.
type roomCatalog struct {
	node       *Node
	id         []byte
	mu         sync.Mutex
	own        map[string]community.RoomCardV1
	cards      map[string]catalogCard
	bytes      int
	peers      map[*peer]tonoverlay.Node
	pub        atomic.Pointer[roomPublication]
	advertised chan tonoverlay.Node
}

func newRoomCatalog(n *Node) (*roomCatalog, error) {
	id, err := ov.PublicRoomsID()
	if err != nil {
		return nil, err
	}
	c := &roomCatalog{node: n, id: id, own: make(map[string]community.RoomCardV1), cards: make(map[string]catalogCard), peers: make(map[*peer]tonoverlay.Node), advertised: make(chan tonoverlay.Node, maxGossipNodes)}
	return c, c.refreshOwn(n.ctx, time.Now())
}

func freshCard(version int32, now time.Time) bool {
	age := now.Unix() - int64(version)
	return age >= -60 && age <= 600
}

func cloneCard(card community.RoomCardV1) community.RoomCardV1 {
	card.RoomKey, card.NodeKey, card.Signature = bytes.Clone(card.RoomKey), bytes.Clone(card.NodeKey), bytes.Clone(card.Signature)
	return card
}

func (c *roomCatalog) refreshOwn(ctx context.Context, now time.Time) error {
	for _, room := range c.node.roomList() {
		if room.role != community.NodeRoleSequencer {
			continue
		}
		state, err := room.store.State(ctx)
		if err != nil {
			return err
		}
		if err := state.Verify(); err != nil {
			return err
		}
		if !bytes.Equal(state.RoomID, room.genesis.RoomKey) {
			return community.ErrWrongRoom
		}
		card, err := community.SignRoomCardV1(room.roomKey, community.RoomCardV1{RoomKey: room.genesis.RoomKey, NodeKey: room.genesis.NodeKey, Name: state.Name, Description: state.Description, Version: int32(now.Unix())})
		if err != nil {
			return err
		}
		c.mu.Lock()
		if old, ok := c.own[string(card.RoomKey)]; !ok || card.Version > old.Version {
			c.own[string(card.RoomKey)] = card
		}
		c.mu.Unlock()
	}
	return nil
}

func (c *roomCatalog) expireLocked(now time.Time) {
	for key, entry := range c.cards {
		if !freshCard(entry.card.Version, now) {
			c.bytes -= entry.size
			delete(c.cards, key)
		}
	}
	for key, card := range c.own {
		if !freshCard(card.Version, now) {
			delete(c.own, key)
		}
	}
}

func (c *roomCatalog) accept(ctx context.Context, card community.RoomCardV1, now time.Time) bool {
	if card.Verify() != nil || community.ValidateMetadata(card.Name, card.Description) != nil || !freshCard(card.Version, now) {
		return false
	}
	raw, err := community.Encode(card)
	if err != nil || len(raw) > maxCatalogBytes {
		return false
	}
	key := string(card.RoomKey)
	if room := c.node.findRoom(card.RoomKey); room != nil && room.role == community.NodeRoleSequencer {
		return false
	}
	c.mu.Lock()
	_, own := c.own[key]
	old, exists := c.cards[key]
	c.mu.Unlock()
	if own || exists && old.card.Version >= card.Version {
		return false
	}
	hint := ""
	if ctx.Err() == nil && community.IsDomainName(card.Alias) && strings.HasSuffix(card.Alias, ".ton") {
		resolveCtx, cancel := context.WithTimeout(ctx, peerKeepaliveTimeout)
		resolved, err := c.node.resolveRoomAlias(resolveCtx, card.Alias)
		if err == nil && resolveCtx.Err() == nil && bytes.Equal(resolved, card.RoomKey) {
			hint = card.Alias
		}
		cancel()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	if _, own := c.own[key]; own {
		return false
	}
	if old, exists := c.cards[key]; exists {
		if old.card.Version >= card.Version {
			return false
		}
		c.bytes -= old.size
		delete(c.cards, key)
	}
	for len(c.cards) >= maxCatalogCards || c.bytes+len(raw) > maxCatalogBytes {
		oldest := ""
		for id, entry := range c.cards {
			if oldest == "" || entry.card.Version < c.cards[oldest].card.Version {
				oldest = id
			}
		}
		c.bytes -= c.cards[oldest].size
		delete(c.cards, oldest)
	}
	c.cards[key] = catalogCard{card: cloneCard(card), aliasHint: hint, size: len(raw)}
	c.bytes += len(raw)
	return true
}

func (c *roomCatalog) list(limit int32, now time.Time) community.RoomCardListV1 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	var cards []community.RoomCardV1
	for _, card := range c.own {
		if freshCard(card.Version, now) {
			cards = append(cards, cloneCard(card))
		}
	}
	for _, entry := range c.cards {
		cards = append(cards, cloneCard(entry.card))
	}
	// There is no cursor in getRoomCardsV1. Sample bounded pages so repeated
	// pulls can discover more than the first 256 advertisements.
	rand.Shuffle(len(cards), func(i, j int) { cards[i], cards[j] = cards[j], cards[i] })
	result := community.RoomCardListV1{}
	header, _ := community.Encode(result)
	size := len(header)
	for _, card := range cards {
		if len(result.Cards) >= int(limit) {
			break
		}
		raw, err := community.Encode(card)
		if err == nil && size+len(raw) <= roomnet.MaxAnswerPayloadSize {
			result.Cards = append(result.Cards, card)
			size += len(raw)
		}
	}
	return result
}

func (n *Node) answerRoomCards(q *roomnet.Query, now time.Time) error {
	var request community.GetRoomCardsV1
	switch value := q.Data.(type) {
	case community.GetRoomCardsV1:
		request = value
	case *community.GetRoomCardsV1:
		request = *value
	}
	limit, err := request.PageLimit()
	if err != nil {
		return q.Answer(community.SubmitRejected{Code: community.RejectMalformedRequest, Message: "invalid room-card limit"})
	}
	if n.catalog == nil {
		return q.Answer(community.RoomCardListV1{})
	}
	return q.Answer(n.catalog.list(limit, now))
}

func (c *roomCatalog) forgetPeer(p *peer) { c.mu.Lock(); delete(c.peers, p); c.mu.Unlock() }

func (c *roomCatalog) nodes(now time.Time) tonoverlay.NodesList {
	self, err := c.node.signedOverlayNode(c.id)
	if err != nil {
		return tonoverlay.NodesList{}
	}
	list := []tonoverlay.Node{self}
	c.mu.Lock()
	defer c.mu.Unlock()
	for p, nd := range c.peers {
		if !freshCard(nd.Version, now) {
			delete(c.peers, p)
			continue
		}
		if len(list) < 8 && c.node.outboundReady(p) {
			list = append(list, nd)
		}
	}
	return tonoverlay.NodesList{List: list}
}

func (c *roomCatalog) queue(nodes []tonoverlay.Node) {
	if c.pub.Load() == nil {
		return
	}
	for _, nd := range capNodes(nodes) {
		id, _, err := verifyOverlayNode(&nd, c.id, time.Now())
		if err != nil || bytes.Equal(id, c.node.qgw.ID()) {
			continue
		}
		select {
		case c.advertised <- nd:
		default:
		}
	}
}

func (c *roomCatalog) answerPeers(q *roomnet.Query) error {
	if selected, err := q.SelectOverlay(c.id); err != nil || !selected {
		return err
	}
	var advertised tonoverlay.NodesList
	switch request := q.Data.(type) {
	case tonoverlay.GetRandomPeers:
		advertised = request.List
	case *tonoverlay.GetRandomPeers:
		advertised = request.List
	default:
		return roomnet.ErrNoAnswer
	}
	c.queue(advertised.List)
	return q.Answer(c.nodes(time.Now()))
}

func (c *roomCatalog) probe(ctx context.Context, p *peer) {
	queryCtx, cancel := context.WithTimeout(ctx, peerKeepaliveTimeout)
	defer cancel()
	self, err := c.node.signedOverlayNode(c.id)
	if err != nil {
		return
	}
	var peers tonoverlay.NodesList
	valid := false
	err = p.withOutbound(func(conn *roomnet.Peer) error {
		if err := conn.QueryOverlayOutbound(queryCtx, c.id, tonoverlay.GetRandomPeers{List: tonoverlay.NodesList{List: []tonoverlay.Node{self}}}, &peers); err != nil {
			return err
		}
		peers.List = capNodes(peers.List)
		for _, nd := range peers.List {
			_, public, err := verifyOverlayNode(&nd, c.id, time.Now())
			if err == nil && public.Equal(p.conn.GetPubKey()) && c.node.outboundReady(p) {
				c.mu.Lock()
				c.peers[p] = nd
				c.mu.Unlock()
				valid = true
				break
			}
		}
		return nil
	})
	if err != nil || !valid {
		c.forgetPeer(p)
		return
	}
	c.node.peers.markNodeGood(p.id, time.Now())
	c.queue(peers.List)
	var cards community.RoomCardListV1
	if err := p.queryNode(queryCtx, community.GetRoomCardsV1{Limit: community.MaxPageLimit}, &cards); err != nil || len(cards.Cards) > community.MaxPageLimit {
		return
	}
	for _, card := range cards.Cards {
		if ctx.Err() != nil {
			return
		}
		c.accept(queryCtx, card, time.Now())
	}
}

func (c *roomCatalog) consider(ctx context.Context, nd tonoverlay.Node) {
	pub := c.pub.Load()
	if pub == nil {
		return
	}
	id, public, err := verifyOverlayNode(&nd, c.id, time.Now())
	if err != nil || bytes.Equal(id, c.node.qgw.ID()) {
		return
	}
	if p, ok := c.node.peers.get(fmt.Sprintf("%x", id)); ok && c.node.outboundReady(p) {
		c.mu.Lock()
		_, known := c.peers[p]
		c.mu.Unlock()
		if !known {
			c.probe(ctx, p)
		}
		return
	}
	if !c.node.acquireDial() {
		return
	}
	defer c.node.releaseDial()
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	addresses, resolved, err := pub.ResolveAll(dialCtx, id)
	if err != nil || !public.Equal(resolved) {
		return
	}
	for _, address := range addresses {
		p, err := c.node.dialCatalogNode(dialCtx, public, address)
		if err == nil {
			c.probe(ctx, p)
			return
		}
	}
}

func (c *roomCatalog) discover(ctx context.Context) {
	if pub := c.pub.Load(); pub != nil {
		if nodes, err := pub.FindOverlayNodes(ctx, []byte(ov.PublicRooms)); err == nil && nodes != nil {
			for _, nd := range capNodes(nodes.List) {
				c.consider(ctx, nd)
			}
		}
	}
	c.mu.Lock()
	peers := make([]*peer, 0, len(c.peers))
	for p := range c.peers {
		peers = append(peers, p)
	}
	c.expireLocked(time.Now())
	c.mu.Unlock()
	for _, p := range peers {
		if ctx.Err() != nil {
			return
		}
		c.probe(ctx, p)
	}
}

func (c *roomCatalog) run(ctx context.Context) {
	// New may precede Run by more than a card TTL. Start with current cards.
	if err := c.refreshOwn(ctx, time.Now()); err != nil && ctx.Err() == nil {
		log.Printf("room cards: %v", err)
	}
	// Refresh must not wait behind network discovery or alias resolution.
	var refresh sync.WaitGroup
	refresh.Add(1)
	go func() {
		defer refresh.Done()
		ticker := time.NewTicker(dht.RepublishEach)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.refreshOwn(ctx, time.Now()); err != nil && ctx.Err() == nil {
					log.Printf("room cards: %v", err)
				}
			}
		}
	}()
	defer refresh.Wait()
	discover := time.NewTimer(discoverWarmup)
	defer discover.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-discover.C:
			c.discover(ctx)
			discover.Reset(DiscoverEach)
		case nd := <-c.advertised:
			c.consider(ctx, nd)
		}
	}
}
