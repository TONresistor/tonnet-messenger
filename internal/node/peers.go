package node

import (
	"math/rand"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
)

const (
	DefaultMaxLeaves = 2048

	perPeerBurst      = 128
	perPeerRefillRate = 64
)

type peerKind int

const (
	kindLeaf peerKind = iota
	kindNode
)

type peer struct {
	id       string
	kind     peerKind
	w        *tonoverlay.ADNLOverlayWrapper
	raw      adnl.Peer
	member   bool
	replayed bool
	errs     int
	signed   *tonoverlay.Node
	limiter  *tokenBucket
}

type peerTable struct {
	maxLeaves int

	mu    sync.RWMutex
	m     map[string]*peer
	known map[string]bool
}

func newPeerTable(maxLeaves int) *peerTable {
	if maxLeaves <= 0 {
		maxLeaves = DefaultMaxLeaves
	}
	return &peerTable{maxLeaves: maxLeaves, m: map[string]*peer{}, known: map[string]bool{}}
}

func (t *peerTable) addInbound(id string, w *tonoverlay.ADNLOverlayWrapper, raw adnl.Peer) (*peer, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.m[id]; ok {
		return p, false
	}
	kind := kindLeaf
	if t.known[id] {
		kind = kindNode
	}
	if kind == kindLeaf && t.leafCountLocked() >= t.maxLeaves {
		return nil, false
	}
	p := &peer{id: id, kind: kind, w: w, raw: raw, limiter: newTokenBucket(perPeerBurst, perPeerRefillRate)}
	t.m[id] = p
	return p, true
}

func (t *peerTable) get(id string) (*peer, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.m[id]
	return p, ok
}

func (t *peerTable) addNode(id string, w *tonoverlay.ADNLOverlayWrapper, raw adnl.Peer, signed *tonoverlay.Node) (*peer, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.known[id] = true
	if p, ok := t.m[id]; ok {
		p.kind = kindNode
		p.member = false
		if signed != nil {
			p.signed = signed
		}
		return p, false
	}
	p := &peer{id: id, kind: kindNode, w: w, raw: raw, signed: signed, limiter: newTokenBucket(perPeerBurst, perPeerRefillRate)}
	t.m[id] = p
	return p, true
}

func (t *peerTable) markKnown(id string) {
	t.mu.Lock()
	t.known[id] = true
	t.mu.Unlock()
}

func (t *peerTable) setSigned(id string, signed *tonoverlay.Node) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.known[id] = true
	p, ok := t.m[id]
	if !ok {
		return false
	}
	p.kind = kindNode
	p.member = false
	if signed != nil {
		p.signed = signed
	}
	return true
}

func (t *peerTable) markMember(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	if !ok || p.kind != kindLeaf || p.member {
		return false
	}
	p.member = true
	return true
}

func (t *peerTable) remove(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, id)
}

func (t *peerTable) memberLeaves(exclude string) []*peer {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*peer, 0, len(t.m))
	for id, p := range t.m {
		if id == exclude {
			continue
		}
		if p.kind == kindLeaf && p.member {
			out = append(out, p)
		}
	}
	return out
}

func (t *peerTable) nodeTargets(exclude string, max int) []*peer {
	t.mu.RLock()
	out := make([]*peer, 0, len(t.m))
	for id, p := range t.m {
		if id == exclude {
			continue
		}
		if p.kind == kindNode {
			out = append(out, p)
		}
	}
	t.mu.RUnlock()

	if max <= 0 || len(out) <= max {
		return out
	}
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out[:max]
}

func (t *peerTable) markReplayed(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	if !ok || p.kind != kindLeaf || p.replayed {
		return false
	}
	p.replayed = true
	return true
}

func (t *peerTable) countError(id string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	if !ok {
		return 0
	}
	p.errs++
	return p.errs
}

func (t *peerTable) nodePeers() []*peer {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*peer, 0)
	for _, p := range t.m {
		if p.kind == kindNode {
			out = append(out, p)
		}
	}
	return out
}

func (t *peerTable) signedNodes() []tonoverlay.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]tonoverlay.Node, 0)
	for _, p := range t.m {
		if p.kind == kindNode && p.signed != nil {
			out = append(out, *p.signed)
		}
	}
	return out
}

func (t *peerTable) counts() (members, nodes int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, p := range t.m {
		switch {
		case p.kind == kindNode:
			nodes++
		case p.member:
			members++
		}
	}
	return
}

func (t *peerTable) leafCountLocked() int {
	n := 0
	for _, p := range t.m {
		if p.kind == kindLeaf {
			n++
		}
	}
	return n
}

type tokenBucket struct {
	mu           sync.Mutex
	tokens       float64
	max          float64
	refillPerSec float64
	last         time.Time
}

func newTokenBucket(max, refillPerSec float64) *tokenBucket {
	return &tokenBucket{tokens: max, max: max, refillPerSec: refillPerSec, last: time.Now()}
}

func (b *tokenBucket) allow() bool { return b.take(1) }

func (b *tokenBucket) take(n float64) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.refillPerSec
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.last = now
	if b.tokens >= n {
		b.tokens -= n
		return true
	}
	return false
}
