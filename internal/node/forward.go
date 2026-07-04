package node

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"log"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/envelope"
	"github.com/TONresistor/tonnet-messenger/internal/room"
	"github.com/TONresistor/tonnet-messenger/internal/tonproof"
)

const relayTimeout = 8 * time.Second

func (n *Node) wirePeer(p *peer) {
	id := p.id

	p.w.SetCustomMessageHandler(func(msg *adnl.MessageCustom) error {
		if !p.limiter.allow() {
			return nil
		}
		if n.peers.markMember(id) {
			log.Printf("member joined %s… (%s)", short(id), n.countsString())
			n.replayHistory(p)
		} else if p.kind == kindLeaf && isHello(msg.Data) {
			n.replayHistory(p)
		}
		n.onOverlayData(id, msg.Data)
		return nil
	})

	p.w.SetBroadcastHandlerWithInfo(func(msg tl.Serializable, _ tonoverlay.BroadcastInfo) error {
		if !p.limiter.allow() {
			return nil
		}
		n.onOverlayData(id, msg)
		return nil
	})

	p.w.SetQueryHandler(func(q *adnl.MessageQuery) error {
		return n.answerQuery(p, q)
	})

	p.w.SetDisconnectHandler(func(addr string, _ ed25519.PublicKey) {
		n.peers.remove(id)
		log.Printf("peer left    %s… (%s)", short(id), n.countsString())
	})
}

func (n *Node) onOverlayData(fromID string, data tl.Serializable) {
	cid := contentID(data)
	if cid != nil && n.dedup.Seen(cid) {
		return
	}
	if rm, ok := asRawMessage(data); ok {
		if !proven(rm.Data) {
			return
		}
		n.room.Observe(rm.Data)
	}
	n.relay(fromID, data)
}

func proven(inner []byte) bool {
	env, err := envelope.Unmarshal(inner)
	if err != nil {
		return false
	}
	if env.Verify() != nil {
		return false
	}
	_, err = tonproof.Verify(env, time.Now())
	return err == nil
}

func (n *Node) relay(fromID string, data tl.Serializable) {
	for _, p := range n.peers.relayTargets(fromID) {
		go func(p *peer) {
			ctx, cancel := context.WithTimeout(context.Background(), relayTimeout)
			defer cancel()
			if err := p.w.SendCustomMessage(ctx, data); err != nil {
				log.Printf("relay to %s… failed: %v", short(p.id), err)
			}
		}(p)
	}
}

func (n *Node) replayHistory(p *peer) {
	recent := n.room.Recent()
	if len(recent) == 0 {
		return
	}
	go func() {
		for _, inner := range recent {
			ctx, cancel := context.WithTimeout(context.Background(), relayTimeout)
			_ = p.w.SendCustomMessage(ctx, room.RawMessage{Data: inner})
			cancel()
		}
	}()
}

func contentID(data tl.Serializable) []byte {
	if rm, ok := asRawMessage(data); ok {
		h := sha256.Sum256(rm.Data)
		return h[:]
	}
	b, err := tl.Serialize(data, true)
	if err != nil {
		return nil
	}
	h := sha256.Sum256(b)
	return h[:]
}

func asRawMessage(data tl.Serializable) (room.RawMessage, bool) {
	switch v := data.(type) {
	case room.RawMessage:
		return v, true
	case *room.RawMessage:
		return *v, true
	}
	return room.RawMessage{}, false
}

func isHello(data tl.Serializable) bool {
	rm, ok := asRawMessage(data)
	if !ok {
		return false
	}
	env, err := envelope.Unmarshal(rm.Data)
	if err != nil {
		return false
	}
	return env.Type == "hello"
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
