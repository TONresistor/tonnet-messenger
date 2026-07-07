package node

import (
	"context"
	"log"
	"time"
)

const (
	peerMaintenanceEach  = 30 * time.Second
	peerKeepaliveIdle    = 45 * time.Second
	peerKeepaliveTimeout = 5 * time.Second
)

func (n *Node) peerMaintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(peerMaintenanceEach)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			for _, p := range n.peers.evictStale(now) {
				n.closePeer(p, "quarantine expired")
			}
			for _, p := range n.peers.nodePeersIdleSince(now, peerKeepaliveIdle) {
				go n.keepalivePeer(ctx, p)
			}
		}
	}
}

func (n *Node) keepalivePeer(ctx context.Context, p *peer) {
	if p == nil || p.raw == nil {
		return
	}
	kctx, cancel := context.WithTimeout(ctx, peerKeepaliveTimeout)
	defer cancel()
	if _, err := p.raw.Ping(kctx); err != nil {
		log.Printf("keepalive to %s… failed: %v", short(p.id), err)
		n.peerFailure(p, time.Now(), "keepalive failed")
		return
	}
	n.peers.markNodeGood(p.id, time.Now())
}

func (n *Node) peerFailure(p *peer, now time.Time, reason string) {
	if p == nil {
		return
	}
	failures, evicted := n.peers.markFailure(p.id, now)
	if failures == 0 {
		return
	}
	if evicted == nil {
		log.Printf("peer warning %s…: %s (%d/%d failures)", short(p.id), reason, failures, peerMaxFailures)
		return
	}
	n.closePeer(evicted, reason)
}

func (n *Node) closePeer(p *peer, reason string) {
	if p == nil {
		return
	}
	log.Printf("peer evicted %s…: %s (%s)", short(p.id), reason, n.countsString())
	if p.w != nil {
		p.w.Close()
	}
	if p.raw != nil {
		p.raw.Close()
	}
}
