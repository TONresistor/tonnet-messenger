package node

import (
	"container/list"
	"encoding/hex"
	"sync"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
)

const (
	sigPenalty   = 5 * time.Second
	maxPenalties = 4096

	globalMessageBurst  = 64
	globalMessageRefill = 32.0
	globalByteBurst     = 256 * 1024
	globalByteRefill    = 128 * 1024.0

	globalQueryBurst  = 128
	globalQueryRefill = 64.0

	sourceMsgsPerMinute  = 30
	sourceBytesPerMinute = 64 * 1024
	maxSourceLimiters    = 4096

	uncertifiedBurst  = 8
	uncertifiedRefill = 4.0 / 60.0

	certCacheCap   = 128
	certMissBurst  = 60
	certMissRefill = 1.0

	deviceBindTTL     = 90 * time.Second
	maxDeviceBind     = 4096
	maxPeersPerDevice = 4

	wrapperStoreCap = 128
)

type penaltyBox struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newPenaltyBox() *penaltyBox {
	return &penaltyBox{m: map[string]time.Time{}}
}

func (b *penaltyBox) punish(id string, now time.Time) {
	b.mu.Lock()
	for peerID, until := range b.m {
		if !until.After(now) {
			delete(b.m, peerID)
		}
	}
	if _, exists := b.m[id]; !exists && len(b.m) >= maxPenalties {
		var oldestID string
		var oldest time.Time
		for peerID, until := range b.m {
			if oldestID == "" || until.Before(oldest) {
				oldestID, oldest = peerID, until
			}
		}
		delete(b.m, oldestID)
	}
	b.m[id] = now.Add(sigPenalty)
	b.mu.Unlock()
}

func (b *penaltyBox) banned(id string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.m[id]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(b.m, id)
		return false
	}
	return true
}

type sourceBucket struct {
	msgs  *tokenBucket
	bytes *tokenBucket
	last  time.Time
}

type dualLimiter struct {
	mu sync.Mutex

	messages, messageMax, messageRefill float64
	bytes, byteMax, byteRefill          float64
	last                                time.Time
}

func newDualLimiter() *dualLimiter {
	return &dualLimiter{
		messages:      globalMessageBurst,
		messageMax:    globalMessageBurst,
		messageRefill: globalMessageRefill,
		bytes:         globalByteBurst,
		byteMax:       globalByteBurst,
		byteRefill:    globalByteRefill,
		last:          time.Now(),
	}
}

func (l *dualLimiter) allow(size int, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	elapsed := now.Sub(l.last).Seconds()
	if elapsed > 0 {
		l.messages = min(l.messageMax, l.messages+elapsed*l.messageRefill)
		l.bytes = min(l.byteMax, l.bytes+elapsed*l.byteRefill)
		l.last = now
	}
	if l.messages < 1 || l.bytes < float64(size) {
		return false
	}
	l.messages--
	l.bytes -= float64(size)
	return true
}

type sourceLimits struct {
	mu sync.Mutex
	m  map[string]*sourceBucket
}

func newSourceLimits() *sourceLimits {
	return &sourceLimits{m: map[string]*sourceBucket{}}
}

func (s *sourceLimits) allow(key string, size int, now time.Time) bool {
	s.mu.Lock()
	b, ok := s.m[key]
	if !ok {
		if len(s.m) >= maxSourceLimiters {
			s.evictOldestLocked()
		}
		b = &sourceBucket{
			msgs:  newTokenBucket(sourceMsgsPerMinute, sourceMsgsPerMinute/60.0),
			bytes: newTokenBucket(sourceBytesPerMinute, sourceBytesPerMinute/60.0),
		}
		s.m[key] = b
	}
	b.last = now
	s.mu.Unlock()
	return b.msgs.take(1) && b.bytes.take(float64(size))
}

func (s *sourceLimits) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, b := range s.m {
		if first || b.last.Before(oldest) {
			oldest, oldestKey, first = b.last, k, false
		}
	}
	if oldestKey != "" {
		delete(s.m, oldestKey)
	}
}

type certEntry struct {
	expireAt int64
	maxSize  uint32
}

type certCache struct {
	mu    sync.Mutex
	order *list.List
	index map[string]*list.Element
	vals  map[string]certEntry
	miss  *tokenBucket
}

func newCertCache() *certCache {
	return &certCache{
		order: list.New(),
		index: map[string]*list.Element{},
		vals:  map[string]certEntry{},
		miss:  newTokenBucket(certMissBurst, certMissRefill),
	}
}

func (c *certCache) get(key string) (certEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.index[key]
	if !ok {
		return certEntry{}, false
	}
	c.order.MoveToBack(el)
	return c.vals[key], true
}

func (c *certCache) put(key string, e certEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.index[key]; ok {
		c.order.MoveToBack(el)
		c.vals[key] = e
		return
	}
	c.index[key] = c.order.PushBack(key)
	c.vals[key] = e
	for c.order.Len() > certCacheCap {
		oldest := c.order.Front()
		if oldest == nil {
			break
		}
		k := oldest.Value.(string)
		c.order.Remove(oldest)
		delete(c.index, k)
		delete(c.vals, k)
	}
}

func (c *certCache) allowMiss() bool { return c.miss.take(1) }

type deviceBinding struct {
	peerID string
	at     time.Time
}

type deviceTable struct {
	mu sync.Mutex
	m  map[string]map[string]deviceBinding
	n  int
}

func newDeviceTable() *deviceTable {
	return &deviceTable{m: map[string]map[string]deviceBinding{}}
}

func (t *deviceTable) bind(key, peerID string, now time.Time) {
	if key == "" || peerID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(now)
	bindings := t.m[key]
	if bindings == nil {
		bindings = map[string]deviceBinding{}
		t.m[key] = bindings
	}
	if _, exists := bindings[peerID]; !exists && len(bindings) >= maxPeersPerDevice {
		var oldestPeer string
		var oldest time.Time
		for id, binding := range bindings {
			if oldestPeer == "" || binding.at.Before(oldest) {
				oldestPeer, oldest = id, binding.at
			}
		}
		delete(bindings, oldestPeer)
		t.n--
	}
	if _, exists := bindings[peerID]; !exists && t.n >= maxDeviceBind {
		t.evictOldestLocked()
		if t.m[key] == nil {
			t.m[key] = bindings
		}
	}
	if _, exists := bindings[peerID]; !exists {
		t.n++
	}
	bindings[peerID] = deviceBinding{peerID: peerID, at: now}
}

func (t *deviceTable) lookup(key string, now time.Time) (string, bool) {
	all := t.lookupAll(key, now)
	if len(all) == 0 {
		return "", false
	}
	return all[0], true
}

func (t *deviceTable) lookupAll(key string, now time.Time) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(now)
	bindings := t.m[key]
	out := make([]string, 0, len(bindings))
	for peerID := range bindings {
		out = append(out, peerID)
	}
	return out
}

func (t *deviceTable) removePeer(peerID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, bindings := range t.m {
		if _, ok := bindings[peerID]; ok {
			delete(bindings, peerID)
			t.n--
		}
		if len(bindings) == 0 {
			delete(t.m, key)
		}
	}
}

func (t *deviceTable) sweepLocked(now time.Time) {
	for key, bindings := range t.m {
		for peerID, binding := range bindings {
			if now.Sub(binding.at) > deviceBindTTL {
				delete(bindings, peerID)
				t.n--
			}
		}
		if len(bindings) == 0 {
			delete(t.m, key)
		}
	}
}

func (t *deviceTable) evictOldestLocked() {
	var oldestKey, oldestPeer string
	var oldest time.Time
	first := true
	for key, bindings := range t.m {
		for peerID, binding := range bindings {
			if first || binding.at.Before(oldest) {
				oldest, oldestKey, oldestPeer, first = binding.at, key, peerID, false
			}
		}
	}
	if oldestKey != "" {
		delete(t.m[oldestKey], oldestPeer)
		t.n--
		if len(t.m[oldestKey]) == 0 {
			delete(t.m, oldestKey)
		}
	}
}

type wrapperStore struct {
	mu    sync.Mutex
	order *list.List
	index map[string]*list.Element
	vals  map[string]broadcast.Broadcast
}

func newWrapperStore() *wrapperStore {
	return &wrapperStore{
		order: list.New(),
		index: map[string]*list.Element{},
		vals:  map[string]broadcast.Broadcast{},
	}
}

func (s *wrapperStore) put(id []byte, b broadcast.Broadcast) {
	k := hex.EncodeToString(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.index[k]; ok {
		s.order.MoveToBack(el)
		s.vals[k] = b
		return
	}
	s.index[k] = s.order.PushBack(k)
	s.vals[k] = b
	for s.order.Len() > wrapperStoreCap {
		oldest := s.order.Front()
		if oldest == nil {
			break
		}
		ok := oldest.Value.(string)
		s.order.Remove(oldest)
		delete(s.index, ok)
		delete(s.vals, ok)
	}
}

func (s *wrapperStore) get(hash []byte) (broadcast.Broadcast, bool) {
	k := hex.EncodeToString(hash)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.vals[k]
	return b, ok
}
