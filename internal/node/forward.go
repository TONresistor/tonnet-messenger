package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"time"

	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

const (
	relayTimeout      = 8 * time.Second
	nodeFanout        = 5
	badScoreRateLimit = 1
)

type outboundJob struct {
	room  *roomContext
	node  bool
	items []tl.Serializable

	physical     *quic.Client
	subscription *inboxSubscription
}

func (n *Node) wirePeer(p *peer) {
	id := p.id
	go n.outboundWriter(p)
	p.conn.SetMessageHandler(func(message any) error {
		n.handleCommunityMessage(p, message, time.Now())
		return nil
	})
	p.conn.SetQueryHandler(func(query *roomnet.Query) error { return n.answerQuery(p, query) })
	p.conn.SetDisconnectHandler(func(_ string, _ ed25519.PublicKey) {
		p.outboundCaps.Store(nil)
		removed := n.peers.removePeer(id, p)
		n.cleanupRoomPeer(p)
		if removed {
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
			if job.physical != nil {
				n.writeInboxPush(job)
				continue
			}
			for _, item := range job.items {
				ctx, cancel := context.WithTimeout(context.Background(), relayTimeout)
				var err error
				p.outboundMu.RLock()
				if job.node || n.peers.isNode(p) {
					err = p.useOutbound(func(conn *roomnet.Peer) error { return conn.SendOutboundMessage(ctx, item) })
				} else {
					err = p.conn.SendMessage(ctx, item)
				}
				p.outboundMu.RUnlock()
				cancel()
				if err != nil {
					log.Printf("relay to %s… failed: %v", short(p.id), err)
					if !errors.Is(err, errOutboundUnprobed) {
						n.peerFailure(p, time.Now(), "relay failed")
					}
					break
				}
			}
		}
	}
}

func (n *Node) writeInboxPush(job outboundJob) {
	if !n.inbox.subscribed(job.physical, job.subscription) {
		return
	}
	deadline := time.Now().Add(relayTimeout)
	if expiry := time.Unix(job.subscription.expireAt, 0); expiry.Before(deadline) {
		deadline = expiry
	}
	ctx, cancel := context.WithDeadline(job.physical.Context(), deadline)
	defer cancel()
	for _, item := range job.items {
		if err := roomnet.SendMessageOn(ctx, job.physical, item); err != nil {
			log.Printf("inbox push failed: %v", err)
			return
		}
	}
}

func (n *Node) enqueueInbox(p *peer, conn *quic.Client, sub *inboxSubscription, push community.InboxPushV1) bool {
	select {
	case <-p.stop:
		return false
	case <-conn.Context().Done():
		return false
	default:
	}
	select {
	case p.out <- outboundJob{physical: conn, subscription: sub, items: []tl.Serializable{push}}:
		return true
	default:
		n.stats.slowPeerDisconnects.Add(1)
		// This handle cannot select a newer incoming replacement or an outbound
		// path, unlike closing the managed Peer. The committed deposit survives.
		conn.Close()
		return false
	}
}

func (n *Node) enqueue(p *peer, items ...tl.Serializable) bool {
	return n.enqueueRoom(n.room, p, items...)
}

func (n *Node) enqueueRoom(room *roomContext, p *peer, items ...tl.Serializable) bool {
	if p == nil || p.conn == nil || len(items) == 0 {
		return false
	}
	select {
	case <-p.stop:
		return false
	case p.out <- outboundJob{room: room, node: n.peers.isNode(p), items: items}:
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
