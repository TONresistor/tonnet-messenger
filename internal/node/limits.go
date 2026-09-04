package node

import (
	"sync"
	"time"
)

const (
	sigPenalty   = 5 * time.Second
	maxPenalties = 4096

	globalQueryBurst    = 128
	globalQueryRefill   = 64.0
	globalMessageBurst  = 1536
	globalMessageRefill = 768.0

	sourceMsgsPerMinute  = 30
	sourceBytesPerMinute = 64 * 1024
	maxSourceLimiters    = 4096
)

type penaltyBox struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newPenaltyBox() *penaltyBox { return &penaltyBox{m: map[string]time.Time{}} }

func (b *penaltyBox) punish(id string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
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

func newSourceLimits() *sourceLimits { return &sourceLimits{m: map[string]*sourceBucket{}} }

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
	for key, bucket := range s.m {
		if oldestKey == "" || bucket.last.Before(oldest) {
			oldestKey, oldest = key, bucket.last
		}
	}
	delete(s.m, oldestKey)
}
