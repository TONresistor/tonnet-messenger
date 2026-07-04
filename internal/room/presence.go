package room

import (
	"sort"
	"sync"
	"time"
)

const DefaultPresenceTTL = 90 * time.Second

const DefaultMaxPresence = 4096

type Member struct {
	Key      string
	Nick     string
	LastSeen time.Time
}

type presenceEntry struct {
	nick     string
	lastSeen time.Time
}

type Presence struct {
	ttl time.Duration
	max int
	now func() time.Time

	mu   sync.Mutex
	seen map[string]presenceEntry
}

func NewPresence(ttl time.Duration) *Presence {
	if ttl <= 0 {
		ttl = DefaultPresenceTTL
	}
	return &Presence{ttl: ttl, max: DefaultMaxPresence, now: time.Now, seen: map[string]presenceEntry{}}
}

func (p *Presence) Mark(key, nick string) {
	if key == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.seen[key]; !exists && len(p.seen) >= p.max {
		p.evictOldestLocked()
	}
	e := p.seen[key]
	e.lastSeen = p.now()
	if nick != "" {
		e.nick = nick
	}
	p.seen[key] = e
}

func (p *Presence) Sweep() {
	p.mu.Lock()
	p.sweepLocked(p.now().Add(-p.ttl))
	p.mu.Unlock()
}

func (p *Presence) sweepLocked(cutoff time.Time) {
	for k, e := range p.seen {
		if e.lastSeen.Before(cutoff) {
			delete(p.seen, k)
		}
	}
}

func (p *Presence) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range p.seen {
		if first || e.lastSeen.Before(oldest) {
			oldest, oldestKey, first = e.lastSeen, k, false
		}
	}
	if oldestKey != "" {
		delete(p.seen, oldestKey)
	}
}

func (p *Presence) Roster() []Member {
	cutoff := p.now().Add(-p.ttl)

	p.mu.Lock()
	p.sweepLocked(cutoff)
	out := make([]Member, 0, len(p.seen))
	for k, e := range p.seen {
		out = append(out, Member{Key: k, Nick: e.nick, LastSeen: e.lastSeen})
	}
	p.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].Key < out[j].Key
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

func (p *Presence) Count() int {
	return len(p.Roster())
}
