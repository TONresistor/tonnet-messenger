package node

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/dht"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
)

// Global discovery borrows the node's DHT and controlled compatible outbound
// paths. It never installs a room association or forwards room traffic.
type globalOverlay struct {
	node         *Node
	name         string
	id           []byte
	mu           sync.Mutex
	peers        map[*peer]tonoverlay.Node
	pub          atomic.Pointer[roomPublication]
	advertised   chan tonoverlay.Node
	pull         func(context.Context, *peer)
	refreshOwn   func(context.Context, time.Time) error
	expireLocked func(time.Time)
	forgetLocked func(*peer)
}

func newGlobalOverlay(n *Node, name string) (*globalOverlay, error) {
	id, err := ov.ID(name)
	if err != nil {
		return nil, err
	}
	return &globalOverlay{node: n, name: name, id: id, peers: make(map[*peer]tonoverlay.Node), advertised: make(chan tonoverlay.Node, maxGossipNodes)}, nil
}

func (c *globalOverlay) dropLocked(p *peer) {
	delete(c.peers, p)
	if c.forgetLocked != nil {
		c.forgetLocked(p)
	}
}
func (c *globalOverlay) pruneLocked(now time.Time) {
	for p, nd := range c.peers {
		if !freshCard(nd.Version, now) {
			c.dropLocked(p)
		}
	}
	if c.expireLocked != nil {
		c.expireLocked(now)
	}
}
func (c *globalOverlay) forgetPeer(p *peer) { c.mu.Lock(); c.dropLocked(p); c.mu.Unlock() }

func (c *globalOverlay) nodes(now time.Time) tonoverlay.NodesList {
	self, err := c.node.signedOverlayNode(c.id)
	if err != nil {
		return tonoverlay.NodesList{}
	}
	list := []tonoverlay.Node{self}
	c.mu.Lock()
	defer c.mu.Unlock()
	for p, nd := range c.peers {
		if !freshCard(nd.Version, now) {
			c.dropLocked(p)
			continue
		}
		if len(list) < 8 && c.node.outboundReady(p) {
			list = append(list, nd)
		}
	}
	return tonoverlay.NodesList{List: list}
}

func (c *globalOverlay) queue(nodes []tonoverlay.Node) {
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

func (c *globalOverlay) answerPeers(q *roomnet.Query) error {
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

func (c *globalOverlay) probe(ctx context.Context, p *peer) {
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
				if _, exists := c.peers[p]; exists || len(c.peers) < MaxNodePeers {
					c.peers[p] = nd
					valid = true
				}
				c.mu.Unlock()
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
	if c.pull != nil {
		c.pull(queryCtx, p)
	}
}

func (c *globalOverlay) consider(ctx context.Context, nd tonoverlay.Node) {
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

func (c *globalOverlay) discover(ctx context.Context) {
	if pub := c.pub.Load(); pub != nil {
		if nodes, err := pub.FindOverlayNodes(ctx, []byte(c.name)); err == nil && nodes != nil {
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
	c.pruneLocked(time.Now())
	c.mu.Unlock()
	for _, p := range peers {
		if ctx.Err() != nil {
			return
		}
		c.probe(ctx, p)
	}
}

func (c *globalOverlay) seed(ctx context.Context) {
	if pub := c.pub.Load(); pub != nil {
		queryCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()
		if nodes, err := pub.FindOverlayNodes(queryCtx, []byte(c.name)); err == nil && nodes != nil {
			c.queue(nodes.List)
		}
	}
}

func (c *globalOverlay) run(ctx context.Context) {
	if err := c.refreshOwn(ctx, time.Now()); err != nil && ctx.Err() == nil {
		log.Printf("%s cards: %v", c.name, err)
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(dht.RepublishEach)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.refreshOwn(ctx, time.Now()); err != nil && ctx.Err() == nil {
					log.Printf("%s cards: %v", c.name, err)
				}
			}
		}
	}()
	go func() {
		defer workers.Done()
		timer := time.NewTimer(discoverWarmup)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				c.seed(ctx)
				timer.Reset(DiscoverEach)
			}
		}
	}()
	defer workers.Wait()
	ticker := time.NewTicker(DiscoverEach)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case nd := <-c.advertised:
			c.consider(ctx, nd)
		case <-ticker.C:
			c.mu.Lock()
			c.pruneLocked(time.Now())
			peers := make([]*peer, 0, len(c.peers))
			for p := range c.peers {
				peers = append(peers, p)
			}
			c.mu.Unlock()
			for _, p := range peers {
				if ctx.Err() != nil {
					return
				}
				c.probe(ctx, p)
			}
		}
	}
}
