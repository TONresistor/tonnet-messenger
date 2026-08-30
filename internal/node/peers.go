package node

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
)

const (
	DefaultMaxLeaves = 256
	MaxLeavesLimit   = 2048
	MaxNodePeers     = 16
	MaxPendingPeers  = 100
	maxKnownNodes    = 256
	outboundQueueCap = 32

	leafPeerBurst      = 4
	leafPeerRefillRate = 2
	nodePeerBurst      = 32
	nodePeerRefillRate = 16
)

type peerKind int

const (
	kindLeaf peerKind = iota
	kindNode
)

type peerState int

const (
	peerQuarantine peerState = iota
	peerHealthy
	peerBad
)

const (
	peerQuarantineTTL = 30 * time.Second
	peerMemberIdleTTL = 150 * time.Second
	peerBadScoreEvict = 8
	peerMaxFailures   = 3
)

type peer struct {
	id              string
	kind            peerKind
	state           peerState
	w               *tonoverlay.ADNLOverlayWrapper
	raw             adnl.Peer
	member          bool
	replayed        bool
	errs            int
	badScore        int
	failures        int
	firstSeen       time.Time
	lastSeen        time.Time
	lastGood        time.Time
	signed          *tonoverlay.Node
	challenge       []byte
	challengeUntil  time.Time
	challengeReplay bool
	boundKey        string
	limiterMu       sync.RWMutex
	limiter         *tokenBucket
	out             chan outboundJob
	stop            chan struct{}
	stopOnce        sync.Once
}

type peerTable struct {
	maxLeaves int

	mu    sync.RWMutex
	m     map[string]*peer
	known map[string]time.Time
}

func newPeerTable(maxLeaves int) *peerTable {
	if maxLeaves <= 0 {
		maxLeaves = DefaultMaxLeaves
	}
	return &peerTable{maxLeaves: maxLeaves, m: map[string]*peer{}, known: map[string]time.Time{}}
}

func newPeer(id string, kind peerKind, w *tonoverlay.ADNLOverlayWrapper, raw adnl.Peer, signed *tonoverlay.Node) *peer {
	now := time.Now()
	burst, refill := float64(leafPeerBurst), float64(leafPeerRefillRate)
	if kind == kindNode {
		burst, refill = nodePeerBurst, nodePeerRefillRate
	}
	return &peer{
		id:        id,
		kind:      kind,
		state:     peerQuarantine,
		w:         w,
		raw:       raw,
		signed:    signed,
		firstSeen: now,
		lastSeen:  now,
		limiter:   newTokenBucket(burst, refill),
		out:       make(chan outboundJob, outboundQueueCap),
		stop:      make(chan struct{}),
	}
}

func (t *peerTable) addInbound(id string, w *tonoverlay.ADNLOverlayWrapper, raw adnl.Peer) (*peer, bool, *peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.m[id]; ok {
		if p.kind != kindLeaf || p.raw == raw {
			return p, false, nil
		}
		next := newPeer(id, kindLeaf, w, raw, nil)
		t.m[id] = next
		return next, true, p
	}
	kind := kindLeaf
	if _, ok := t.known[id]; ok {
		kind = kindNode
	}
	if kind == kindLeaf && t.pendingCountLocked() >= MaxPendingPeers {
		return nil, false, nil
	}
	if kind == kindNode && t.nodeCountLocked() >= MaxNodePeers {
		return nil, false, nil
	}
	p := newPeer(id, kind, w, raw, nil)
	t.m[id] = p
	return p, true, nil
}

func (t *peerTable) has(id string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.m[id]
	return ok
}

func (t *peerTable) isKnown(id string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.known[id]
	return ok
}

func (t *peerTable) acceptInbound(p *peer, now time.Time) (*peer, bool, bool) {
	if p == nil {
		return nil, false, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	existing, ok := t.m[p.id]
	if !ok || existing != p {
		return nil, false, false
	}
	existing.lastSeen = now
	existing.lastGood = now
	existing.failures = 0
	if existing.badScore > 0 {
		existing.badScore--
	}
	if existing.state == peerQuarantine {
		existing.state = peerHealthy
	}
	if existing.kind != kindLeaf || existing.member {
		return existing, false, true
	}
	if t.memberLeafCountLocked() >= t.maxLeaves {
		return nil, false, false
	}
	existing.member = true
	return existing, true, true
}

func (t *peerTable) get(id string) (*peer, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.m[id]
	return p, ok
}

func (t *peerTable) memberLeaf(id string) (*peer, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.m[id]
	if !ok || p.kind != kindLeaf || !p.member || p.state != peerHealthy {
		return nil, false
	}
	return p, true
}

func (t *peerTable) setChallenge(candidate *peer, nonce []byte, until time.Time) bool {
	return t.setChallengeMode(candidate, nonce, until, false)
}

func (t *peerTable) setSessionChallenge(candidate *peer, nonce []byte, until time.Time) bool {
	return t.setChallengeMode(candidate, nonce, until, true)
}

func (t *peerTable) setChallengeMode(candidate *peer, nonce []byte, until time.Time, replay bool) bool {
	if candidate == nil || len(nonce) != 32 {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[candidate.id]
	if !ok || p != candidate {
		return false
	}
	p.challenge = append(p.challenge[:0], nonce...)
	p.challengeUntil = until
	p.challengeReplay = replay
	return true
}

func (t *peerTable) authenticateDevice(candidate *peer, key, proof string, allowNew bool, now time.Time) bool {
	if candidate == nil || key == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[candidate.id]
	if !ok || p != candidate || p.kind != kindLeaf || !p.member || p.state != peerHealthy {
		return false
	}
	if p.boundKey == key {
		if allowNew && proof != "" && p.challengeUntil.After(now) {
			decoded, err := hex.DecodeString(proof)
			if err == nil && bytes.Equal(decoded, p.challenge) {
				if p.challengeReplay {
					p.replayed = false
				}
				p.challenge = nil
				p.challengeUntil = time.Time{}
				p.challengeReplay = false
			}
		}
		return true
	}
	if !allowNew || p.boundKey != "" || !p.challengeUntil.After(now) {
		return false
	}
	decoded, err := hex.DecodeString(proof)
	if err != nil || !bytes.Equal(decoded, p.challenge) {
		return false
	}
	p.boundKey = key
	if p.challengeReplay {
		p.replayed = false
	}
	p.challenge = nil
	p.challengeUntil = time.Time{}
	p.challengeReplay = false
	return true
}

func (t *peerTable) addNode(id string, w *tonoverlay.ADNLOverlayWrapper, raw adnl.Peer, signed *tonoverlay.Node) (*peer, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.markKnownLocked(id)
	if p, ok := t.m[id]; ok {
		if p.kind != kindNode && t.nodeCountLocked() >= MaxNodePeers {
			return nil, false
		}
		if p.kind != kindNode {
			p.kind = kindNode
			p.useNodeLimiter()
		}
		p.member = false
		p.lastSeen = time.Now()
		if signed != nil {
			p.signed = signed
		}
		return p, false
	}
	if t.nodeCountLocked() >= MaxNodePeers {
		return nil, false
	}
	p := newPeer(id, kindNode, w, raw, signed)
	t.m[id] = p
	return p, true
}

func (t *peerTable) installOverlay(target *peer, w *tonoverlay.ADNLOverlayWrapper) bool {
	if target == nil || w == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[target.id]
	if !ok || p != target || p.w != nil {
		return false
	}
	p.w = w
	return true
}

func (t *peerTable) markKnown(id string) {
	t.mu.Lock()
	t.markKnownLocked(id)
	t.mu.Unlock()
}

func (t *peerTable) markKnownLocked(id string) {
	if _, exists := t.known[id]; !exists && len(t.known) >= maxKnownNodes {
		var oldestID string
		var oldest time.Time
		for candidate, seen := range t.known {
			if oldestID == "" || seen.Before(oldest) {
				oldestID, oldest = candidate, seen
			}
		}
		delete(t.known, oldestID)
	}
	t.known[id] = time.Now()
}

func (t *peerTable) setSigned(id string, signed *tonoverlay.Node) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.markKnownLocked(id)
	p, ok := t.m[id]
	if !ok {
		return false
	}
	if p.kind != kindNode && t.nodeCountLocked() >= MaxNodePeers {
		return false
	}
	if p.kind != kindNode {
		p.kind = kindNode
		p.useNodeLimiter()
	}
	p.member = false
	p.lastSeen = time.Now()
	if signed != nil {
		p.signed = signed
	}
	return true
}

func (t *peerTable) markMember(id string) bool {
	return t.markAccepted(id, time.Now())
}

func (t *peerTable) markAccepted(id string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	if !ok || p.kind != kindLeaf || p.member {
		return false
	}
	p.state = peerHealthy
	p.member = true
	p.lastSeen = now
	p.lastGood = now
	p.failures = 0
	return true
}

func (t *peerTable) markGood(id string, now time.Time) bool {
	return t.markGoodLockedKind(id, now, false)
}

func (t *peerTable) markNodeGood(id string, now time.Time) bool {
	return t.markGoodLockedKind(id, now, true)
}

func (t *peerTable) markGoodLockedKind(id string, now time.Time, nodeOnly bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	if !ok {
		return false
	}
	if nodeOnly && p.kind != kindNode {
		return false
	}
	p.lastSeen = now
	p.lastGood = now
	p.failures = 0
	if p.badScore > 0 {
		p.badScore--
	}
	if p.state == peerQuarantine {
		p.state = peerHealthy
		return true
	}
	return false
}

func (t *peerTable) markSeen(id string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.m[id]; ok {
		p.lastSeen = now
	}
}

func (t *peerTable) markBad(id string, score int, now time.Time) (int, *peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	if !ok {
		return 0, nil
	}
	if score < 1 {
		score = 1
	}
	p.lastSeen = now
	p.badScore += score
	if p.badScore < peerBadScoreEvict {
		return p.badScore, nil
	}
	p.state = peerBad
	delete(t.m, id)
	return p.badScore, p
}

func (t *peerTable) markFailure(id string, now time.Time) (int, *peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	if !ok {
		return 0, nil
	}
	p.lastSeen = now
	p.failures++
	p.badScore += 2
	if p.failures < peerMaxFailures && p.badScore < peerBadScoreEvict {
		return p.failures, nil
	}
	p.state = peerBad
	delete(t.m, id)
	return p.failures, p
}

func (t *peerTable) evictStale(now time.Time) []*peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []*peer
	for id, p := range t.m {
		if p.kind == kindNode {
			continue
		}
		if p.member {
			if now.Sub(p.lastGood) <= peerMemberIdleTTL {
				continue
			}
			delete(t.m, id)
			out = append(out, p)
			continue
		}
		if now.Sub(p.firstSeen) <= peerQuarantineTTL {
			continue
		}
		delete(t.m, id)
		out = append(out, p)
	}
	return out
}

func (t *peerTable) removePeer(id string, target *peer) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	if !ok {
		return false
	}
	if target != nil && p != target {
		return false
	}
	delete(t.m, id)
	return true
}

func (t *peerTable) memberLeaves(exclude string) []*peer {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*peer, 0, len(t.m))
	for id, p := range t.m {
		if id == exclude {
			continue
		}
		if p.kind == kindLeaf && p.member && p.state == peerHealthy {
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
		if p.kind == kindNode && p.state == peerHealthy {
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

func (t *peerTable) nodePeersIdleSince(now time.Time, idle time.Duration) []*peer {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*peer, 0)
	for _, p := range t.m {
		if p.kind != kindNode || p.state != peerHealthy {
			continue
		}
		last := p.lastGood
		if last.IsZero() {
			last = p.firstSeen
		}
		if now.Sub(last) >= idle {
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
		if p.kind == kindNode && p.state == peerHealthy && p.signed != nil {
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

func (t *peerTable) memberLeafCountLocked() int {
	n := 0
	for _, p := range t.m {
		if p.kind == kindLeaf && p.member {
			n++
		}
	}
	return n
}

func (t *peerTable) pendingCountLocked() int {
	n := 0
	for _, p := range t.m {
		if p.kind == kindLeaf && !p.member {
			n++
		}
	}
	return n
}

func (t *peerTable) nodeCountLocked() int {
	n := 0
	for _, p := range t.m {
		if p.kind == kindNode {
			n++
		}
	}
	return n
}

func (p *peer) allowIngress() bool {
	p.limiterMu.RLock()
	limiter := p.limiter
	p.limiterMu.RUnlock()
	return limiter.allow()
}

func (p *peer) useNodeLimiter() {
	p.limiterMu.Lock()
	p.limiter = newTokenBucket(nodePeerBurst, nodePeerRefillRate)
	p.limiterMu.Unlock()
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
