package node

import (
	"bytes"
	"time"

	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
)

type roomAssociation struct {
	member, node bool
	signed       *tonoverlay.Node
}
type roomPeerView struct {
	table *peerTable
	room  *roomContext
}

func (v roomPeerView) get(id string) (*peer, bool) { return v.table.get(id) }
func (v roomPeerView) acceptInbound(p *peer, now time.Time) (*peer, bool, bool) {
	if p == nil {
		return nil, false, false
	}
	v.table.mu.Lock()
	defer v.table.mu.Unlock()
	p, _, ok := v.table.acceptInboundLocked(p, now)
	if !ok {
		return nil, false, false
	}
	v.room.peersMu.Lock()
	defer v.room.peersMu.Unlock()
	a := v.room.associations[p]
	joined := !a.node && !a.member
	if !a.node {
		a.member = true
	}
	v.room.associations[p] = a
	return p, joined, true
}

func (v roomPeerView) setNode(p *peer, signed *tonoverlay.Node) {
	if p == nil {
		return
	}
	v.table.mu.Lock()
	defer v.table.mu.Unlock()
	if v.table.m[p.id] != p || !v.table.setSignedLocked(p.id, signed) {
		return
	}
	v.room.peersMu.Lock()
	defer v.room.peersMu.Unlock()
	a := v.room.associations[p]
	a.node = true
	a.member = false
	if signed != nil {
		a.signed = signed
	}
	v.room.associations[p] = a
}

func (v roomPeerView) relation(p *peer) (roomAssociation, bool) {
	if p == nil {
		return roomAssociation{}, false
	}
	v.table.mu.RLock()
	defer v.table.mu.RUnlock()
	if v.table.m[p.id] != p || p.state != peerHealthy {
		return roomAssociation{}, false
	}
	v.room.peersMu.RLock()
	defer v.room.peersMu.RUnlock()
	a, ok := v.room.associations[p]
	return a, ok
}
func (v roomPeerView) isHealthyNode(p *peer) bool { a, ok := v.relation(p); return ok && a.node }
func (v roomPeerView) isMember(p *peer) bool {
	a, ok := v.relation(p)
	return ok && a.member && !a.node
}
func (v roomPeerView) acceptsAuthor(p *peer, key []byte) bool {
	if len(key) != 32 {
		return false
	}
	a, ok := v.relation(p)
	return ok && (a.node || (a.member && p.conn != nil && bytes.Equal(p.conn.GetPubKey(), key)))
}

func (v roomPeerView) list(exclude string, nodes bool) []*peer {
	v.table.mu.RLock()
	defer v.table.mu.RUnlock()
	v.room.peersMu.RLock()
	defer v.room.peersMu.RUnlock()
	var out []*peer
	for p, a := range v.room.associations {
		if p.id == exclude || v.table.m[p.id] != p || p.state != peerHealthy {
			continue
		}
		if nodes && a.node && p.outboundCaps.Load() != nil || !nodes && a.member && !a.node {
			out = append(out, p)
		}
	}
	return out
}
func (v roomPeerView) memberLeaves(exclude string) []*peer { return v.list(exclude, false) }
func (v roomPeerView) identityLeaves(key []byte, exclude string) []*peer {
	var out []*peer
	for _, p := range v.memberLeaves(exclude) {
		if p.conn != nil && bytes.Equal(p.conn.GetPubKey(), key) {
			out = append(out, p)
		}
	}
	return out
}
func (v roomPeerView) counts() (members, nodes int) {
	v.table.mu.RLock()
	defer v.table.mu.RUnlock()
	v.room.peersMu.RLock()
	defer v.room.peersMu.RUnlock()
	for p, a := range v.room.associations {
		if v.table.m[p.id] != p || p.state != peerHealthy {
			continue
		}
		if a.node {
			nodes++
		} else if a.member {
			members++
		}
	}
	return
}
func (v roomPeerView) signedNodes() []tonoverlay.Node {
	v.table.mu.RLock()
	defer v.table.mu.RUnlock()
	v.room.peersMu.RLock()
	defer v.room.peersMu.RUnlock()
	var out []tonoverlay.Node
	for p, a := range v.room.associations {
		if a.node && a.signed != nil && v.table.m[p.id] == p && p.state == peerHealthy {
			out = append(out, *a.signed)
		}
	}
	return out
}

func (v roomPeerView) isNode(p *peer) bool {
	v.room.peersMu.RLock()
	defer v.room.peersMu.RUnlock()
	return v.room.associations[p].node
}
