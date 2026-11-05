package node

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math/rand"
	"sync"

	"github.com/xssnick/tonutils-go/adnl/quic"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

var errOutboundUnprobed = errors.New("node: outbound connection has no compatible capabilities")

type nodeDialLock struct {
	mu    sync.Mutex
	users int
}

// Entries exist only while dials are running or queued, bounded by the existing
// dial semaphore. The connection handler never takes these locks or does I/O.
func (n *Node) lockNodeDial(id string) func() {
	n.nodeDialsMu.Lock()
	if n.nodeDials == nil {
		n.nodeDials = make(map[string]*nodeDialLock)
	}
	lock := n.nodeDials[id]
	if lock == nil {
		lock = &nodeDialLock{}
		n.nodeDials[id] = lock
	}
	lock.users++
	n.nodeDialsMu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		n.nodeDialsMu.Lock()
		lock.users--
		if lock.users == 0 {
			delete(n.nodeDials, id)
		}
		n.nodeDialsMu.Unlock()
	}
}

func (n *Node) hasNodeOutbound(p *peer) bool {
	if n.qgw == nil || p == nil || p.conn == nil {
		return false
	}
	raw, err := n.qgw.OutboundPeerDefaultID(p.conn.GetID())
	return err == nil && p.conn.Wraps(raw)
}

// Readiness is only advisory; actual I/O still holds outboundMu and uses the
// strict transport. Comparing the cache token avoids clearing a newer probe.
func (n *Node) outboundReady(p *peer) bool {
	caps := p.outboundCaps.Load()
	if caps == nil {
		return false
	}
	if !n.hasNodeOutbound(p) {
		p.outboundCaps.CompareAndSwap(caps, nil)
		return false
	}
	return p.outboundCaps.Load() == caps
}

func (n *Node) outboundTargets(exclude string, max int) []*peer {
	return n.forRoom(n.room).outboundTargets(exclude, max)
}

func (n *Node) filterOutboundTargets(candidates []*peer, max int) []*peer {
	targets := candidates[:0]
	for _, p := range candidates {
		if n.outboundReady(p) {
			targets = append(targets, p)
		}
	}
	if max > 0 && len(targets) > max {
		rand.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
		targets = targets[:max]
	}
	return targets
}

// dialNode is the only node-runtime boundary allowed to create or replace an
// outbound. Per-key exclusion includes probing. Readers hold outboundMu through
// each strict-outbound operation, so replacement cannot reuse old capabilities
// or race a probe that would later authorize its new connection.
func (n *Node) dialNode(ctx context.Context, public ed25519.PublicKey, address string) (*peer, error) {
	return n.dialNodeTarget(ctx, public, address, true)
}

func (n *Node) dialCatalogNode(ctx context.Context, public ed25519.PublicKey, address string) (*peer, error) {
	return n.dialNodeTarget(ctx, public, address, false)
}

func (n *Node) dialNodeTarget(ctx context.Context, public ed25519.PublicKey, address string, roomScoped bool) (*peer, error) {
	key, err := community.KeyID(public)
	if err != nil {
		return nil, err
	}
	id := hex.EncodeToString(key)
	unlock := n.lockNodeDial(id)
	defer unlock()
	previous, _ := n.peers.get(id)
	if previous == nil {
		// A detached peer's queued leaf writes must not see an outbound added
		// behind their ordinary (inbound-capable) transport wrapper.
		if orphan := n.qgw.Peer(n.cfg.Key.Public().(ed25519.PublicKey), public); orphan != nil {
			orphan.Close()
		}
	}
	if previous != nil {
		previous.outboundMu.Lock()
		defer previous.outboundMu.Unlock()
		n.peers.setSigned(id, nil)
		if n.hasNodeOutbound(previous) && previous.outboundProbed {
			if previous.outboundCaps.Load() != nil {
				if roomScoped {
					n.associateSingleRoom(previous)
				}
				return previous, nil
			}
			if previous.outboundError != nil {
				return nil, previous.outboundError
			}
			return nil, errOutboundUnprobed
		}
		previous.outboundCaps.Store(nil)
		previous.outboundProbed = false
		previous.outboundError = nil
	}
	n.peers.markKnown(id)
	raw, err := n.qgw.DialDefault(ctx, public, address)
	if err != nil {
		return nil, err
	}
	p, ok := n.peers.get(id)
	if !ok || p.conn == nil || !p.conn.Wraps(raw) {
		return nil, errOutboundUnprobed
	}
	if p != previous {
		p.outboundMu.Lock()
		defer p.outboundMu.Unlock()
		p.outboundCaps.Store(nil)
	}
	n.peers.setSigned(id, nil)
	probeCtx, cancel := context.WithTimeout(ctx, peerKeepaliveTimeout)
	capabilities, err := p.conn.ProbeCapabilitiesOutbound(probeCtx)
	cancel()
	if err == nil && !n.hasNodeOutbound(p) {
		err = quic.ErrOutboundPeerNotFound
	}
	p.outboundProbed = true
	p.outboundError = err
	if err != nil {
		return nil, err
	}
	p.outboundCaps.Store(&capabilities)
	if roomScoped {
		n.associateSingleRoom(p)
	}
	return p, nil
}

func (p *peer) withOutbound(operation func(*roomnet.Peer) error) error {
	if p.outboundCaps.Load() == nil {
		return errOutboundUnprobed
	}
	p.outboundMu.RLock()
	defer p.outboundMu.RUnlock()
	return p.useOutbound(operation)
}

// Caller holds outboundMu; kept separate so a writer can classify leaf/node
// traffic under the same lock as a possible outbound dial and role promotion.
func (p *peer) useOutbound(operation func(*roomnet.Peer) error) error {
	if p.conn == nil || p.outboundCaps.Load() == nil {
		return errOutboundUnprobed
	}
	err := operation(p.conn)
	if errors.Is(err, quic.ErrOutboundPeerNotFound) || errors.Is(err, quic.ErrPeerClosed) {
		p.outboundCaps.Store(nil)
	}
	return err
}

func (p *peer) queryNodeRoom(ctx context.Context, room []byte, request, result any) error {
	return p.withOutbound(func(conn *roomnet.Peer) error { return conn.QueryRoomOutbound(ctx, room, request, result) })
}

func (p *peer) queryNode(ctx context.Context, request, result any) error {
	return p.withOutbound(func(conn *roomnet.Peer) error { return conn.QueryOutbound(ctx, request, result) })
}
