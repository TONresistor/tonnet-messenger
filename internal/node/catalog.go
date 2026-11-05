package node

import (
	"bytes"
	"context"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
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
	*globalOverlay
	own   map[string]community.RoomCardV1
	cards map[string]catalogCard
	bytes int
}

func newRoomCatalog(n *Node) (*roomCatalog, error) {
	global, err := newGlobalOverlay(n, ov.PublicRooms)
	if err != nil {
		return nil, err
	}
	c := &roomCatalog{globalOverlay: global, own: make(map[string]community.RoomCardV1), cards: make(map[string]catalogCard)}
	global.refreshOwn = c.refreshOwn
	global.expireLocked = c.expireLocked
	global.pull = c.pullCards
	return c, c.refreshOwn(n.ctx, time.Now())
}

func (c *roomCatalog) pullCards(ctx context.Context, p *peer) {
	var cards community.RoomCardListV1
	if err := p.queryNode(ctx, community.GetRoomCardsV1{Limit: community.MaxPageLimit}, &cards); err != nil || len(cards.Cards) > community.MaxPageLimit {
		return
	}
	for _, card := range cards.Cards {
		if ctx.Err() != nil {
			return
		}
		c.accept(ctx, card, time.Now())
	}
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
