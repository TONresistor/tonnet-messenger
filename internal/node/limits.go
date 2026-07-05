package node

import (
	"container/list"
	"encoding/hex"
	"sync"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
)

const (
	sigPenalty = 5 * time.Second

	sourceMsgsPerMinute  = 30
	sourceBytesPerMinute = 64 * 1024
	maxSourceLimiters    = 4096

	uncertifiedBurst  = 8
	uncertifiedRefill = 4.0 / 60.0

	certCacheCap   = 128
	certMissBurst  = 60
	certMissRefill = 1.0

	deviceBindTTL = 90 * time.Second
	maxDeviceBind = 4096

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
	m  map[string]deviceBinding
}

func newDeviceTable() *deviceTable {
	return &deviceTable{m: map[string]deviceBinding{}}
}

func (t *deviceTable) bind(key, peerID string, now time.Time) {
	if key == "" || peerID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.m[key]; !ok && len(t.m) >= maxDeviceBind {
		t.evictOldestLocked()
	}
	t.m[key] = deviceBinding{peerID: peerID, at: now}
}

func (t *deviceTable) lookup(key string, now time.Time) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.m[key]
	if !ok {
		return "", false
	}
	if now.Sub(b.at) > deviceBindTTL {
		delete(t.m, key)
		return "", false
	}
	return b.peerID, true
}

func (t *deviceTable) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, b := range t.m {
		if first || b.at.Before(oldest) {
			oldest, oldestKey, first = b.at, k, false
		}
	}
	if oldestKey != "" {
		delete(t.m, oldestKey)
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
