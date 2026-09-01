package node

import (
	"context"
	"crypto/ed25519"
	"log"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"
)

const (
	relayTimeout      = 8 * time.Second
	nodeFanout        = 5
	badScoreRateLimit = 1
)

type outboundJob struct {
	items []tl.Serializable
}

func (n *Node) wireUntrackedPeer(id string, wrapper *tonoverlay.ADNLOverlayWrapper, raw adnl.Peer) {
	promote := func() (*peer, bool) {
		p, added, replaced := n.peers.addInbound(id, wrapper, raw)
		if p == nil {
			raw.Close()
			return nil, false
		}
		if replaced != nil {
			closePeerConnection(replaced)
		}
		if !added && p.raw != raw {
			raw.Close()
			return nil, false
		}
		if added {
			n.wirePeer(p)
		}
		return p, true
	}
	wrapper.SetCustomMessageHandler(func(message *adnl.MessageCustom) error {
		p, ok := promote()
		if ok {
			n.handleCommunityMessage(p, message.Data, time.Now())
		}
		return nil
	})
	wrapper.SetQueryHandler(func(query *adnl.MessageQuery) error {
		p, ok := promote()
		if !ok {
			return nil
		}
		return n.answerQuery(p, query)
	})
}

func (n *Node) wirePeer(p *peer) {
	id := p.id
	go n.outboundWriter(p)
	p.w.SetCustomMessageHandler(func(message *adnl.MessageCustom) error {
		n.handleCommunityMessage(p, message.Data, time.Now())
		return nil
	})
	p.w.SetQueryHandler(func(query *adnl.MessageQuery) error { return n.answerQuery(p, query) })
	p.w.SetDisconnectHandler(func(_ string, _ ed25519.PublicKey) {
		if n.peers.removePeer(id, p) {
			p.stopOnce.Do(func() { close(p.stop) })
			log.Printf("peer left    %s… (%s)", short(id), n.countsString())
		}
	})
}

func (n *Node) outboundWriter(p *peer) {
	for {
		select {
		case <-p.stop:
			return
		case job := <-p.out:
			for _, item := range job.items {
				ctx, cancel := context.WithTimeout(context.Background(), relayTimeout)
				err := p.w.SendCustomMessage(ctx, item)
				cancel()
				if err != nil {
					log.Printf("relay to %s… failed: %v", short(p.id), err)
					n.peerFailure(p, time.Now(), "relay failed")
					break
				}
			}
		}
	}
}

func (n *Node) enqueue(p *peer, items ...tl.Serializable) bool {
	if p == nil || p.w == nil || len(items) == 0 {
		return false
	}
	select {
	case <-p.stop:
		return false
	case p.out <- outboundJob{items: items}:
		return true
	default:
		n.stats.slowPeerDisconnects.Add(1)
		n.peers.removePeer(p.id, p)
		n.closePeer(p, "outbound queue full")
		return false
	}
}

func (n *Node) scorePeer(p *peer, score int, now time.Time, reason string) {
	if p == nil {
		return
	}
	total, evicted := n.peers.markBad(p.id, score, now)
	if evicted == nil {
		if total == score || total%peerBadScoreEvict == peerBadScoreEvict-1 {
			log.Printf("peer warning %s…: %s (score %d/%d)", short(p.id), reason, total, peerBadScoreEvict)
		}
		return
	}
	n.closePeer(evicted, reason)
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
