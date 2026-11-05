package node

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/xssnick/tonutils-go/adnl/quic"
)

const (
	peerMaintenanceEach  = 30 * time.Second
	peerKeepaliveIdle    = 45 * time.Second
	peerKeepaliveTimeout = 5 * time.Second
)

func (n *Node) peerMaintenanceLoop(ctx context.Context) {
	var workers sync.WaitGroup
	defer workers.Wait()
	ticker := time.NewTicker(peerMaintenanceEach)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			if n.inbox == nil {
				n.evictIdlePeers(now)
			}
			for _, p := range n.peers.nodePeersIdleSince(now, peerKeepaliveIdle) {
				workers.Add(1)
				go func() { defer workers.Done(); n.keepalivePeer(ctx, p) }()
			}
		}
	}
}

func (n *Node) evictIdlePeers(now time.Time) {
	if n.inbox == nil {
		for _, p := range n.peers.evictStale(now) {
			n.closePeer(p, "leaf activity expired")
		}
		return
	}
	s := n.inbox
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now.Unix())
	for conn, state := range s.connections {
		// Keep the established verified-node lifecycle. The relay rule applies
		// to clients; room membership uses the existing managed-peer model.
		if n.peers.isHealthyNode(state.peer) {
			continue
		}
		member, ok := n.peers.memberLeaf(state.peer.id)
		if state.idleAt(now, ok && member == state.peer) {
			// Serialize the decision with beginQuery. Never close another live
			// connection selected by the managed Peer or a newer replacement.
			conn.Close()
		}
	}
}

func (c *inboxConnection) idleAt(now time.Time, member bool) bool {
	if c.inFlight != 0 {
		return false
	}
	ttl := peerQuarantineTTL
	if member || c.subscription != nil && c.subscription.expireAt > now.Unix() {
		ttl = peerMemberIdleTTL
	}
	return now.Sub(c.lastActivity) >= ttl
}

func (s *inboxService) open(p *peer, conn *quic.Client, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now.Unix())
	if s.closed || conn.Context().Err() != nil || s.connections[conn] != nil {
		return
	}
	if len(s.connections) >= s.maxConnections {
		conn.Close()
		return
	}
	state := &inboxConnection{peer: p, lastActivity: now, challenges: make(map[string]community.InboxAuthV1ToSign)}
	s.connections[conn] = state
	state.stop = context.AfterFunc(conn.Context(), func() {
		s.mu.Lock()
		if s.connections[conn] == state {
			delete(s.connections, conn)
		}
		s.mu.Unlock()
	})
}

func (s *inboxService) beginQuery(ctx context.Context) func(bool) {
	conn, err := quic.ClientFromContext(ctx)
	s.mu.Lock()
	state := s.connections[conn]
	if err != nil || state == nil {
		s.mu.Unlock()
		return func(bool) {}
	}
	state.inFlight++
	s.mu.Unlock()
	finished := make(chan bool, 1)
	context.AfterFunc(ctx, func() {
		// The stream includes the answer write. The handler may have returned
		// its encoded response earlier, or the stream may have been reset.
		answered := <-finished
		s.mu.Lock()
		state.inFlight--
		if answered {
			state.lastActivity = time.Now()
		}
		s.mu.Unlock()
	})
	return func(answered bool) { finished <- answered }
}

func (s *inboxService) pushed(conn *quic.Client, sub *inboxSubscription, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state := s.connections[conn]; state != nil && sub != nil && state.subscription == sub && sub.expireAt > now.Unix() {
		state.lastActivity = now
	}
}

func (n *Node) keepalivePeer(ctx context.Context, p *peer) {
	if p == nil || p.conn == nil {
		return
	}
	kctx, cancel := context.WithTimeout(ctx, peerKeepaliveTimeout)
	defer cancel()
	var remote broadcast.Time
	if err := p.queryNode(kctx, broadcast.GetTime{}, &remote); err != nil {
		if errors.Is(err, errOutboundUnprobed) {
			return
		}
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
	closePeerConnection(p)
}

func closePeerConnection(p *peer) {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() { close(p.stop) })
	if p.conn != nil {
		p.conn.Close()
	}
}
