package client

import (
	"math"
	"math/rand/v2"
	"sort"
	"time"
)

const maxRelayPeers = 256 // The Connector's bound; holders plus top-five must fit.
const maxRelayBans = 4096

type relayObservation uint8

const (
	relaySuccess relayObservation = iota
	relayTimeout
	relayNoAnswer
	relayMalformedAnswer
	relayInvalidSignature
	relayUnsupported
	relayValidUnscored
)

type relayBan struct {
	duration       time.Duration
	until, updated time.Time
}
type relayPolicy struct {
	scores map[string]uint32
	bans   map[string]relayBan
	random *rand.Rand
}

func newRelayPolicy() *relayPolicy {
	return &relayPolicy{scores: make(map[string]uint32), bans: make(map[string]relayBan), random: rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))}
}
func (p *relayPolicy) banned(key string, now time.Time) bool { return now.Before(p.bans[key].until) }
func (p *relayPolicy) observe(key string, outcome relayObservation, now time.Time) {
	u, known := p.scores[key]
	switch outcome {
	case relayTimeout, relayNoAnswer, relayMalformedAnswer:
		if known && u < math.MaxUint32 {
			p.scores[key] = u + 1
		}
	case relaySuccess, relayValidUnscored:
		if known && outcome == relaySuccess && u > 0 {
			p.scores[key] = u - 1
		}
		if b, ok := p.bans[key]; ok {
			b.duration = max(time.Minute, b.duration*2/3)
			b.updated = now
			p.bans[key] = b
		}
	case relayInvalidSignature:
		b, known := p.bans[key]
		if !known {
			if len(p.bans) >= maxRelayBans {
				victim := ""
				for k, v := range p.bans {
					old := p.bans[victim]
					if victim == "" || v.duration < old.duration || v.duration == old.duration && (v.updated.Before(old.updated) || v.updated.Equal(old.updated) && k < victim) {
						victim = k
					}
				}
				delete(p.bans, victim)
			}
			b.duration = time.Minute
		}
		b.until, b.updated = now.Add(b.duration), now
		b.duration = min(time.Hour, b.duration+b.duration/2)
		p.bans[key] = b
	}
}
func (p *relayPolicy) weights(keys []string, now time.Time) map[string]uint64 {
	minU := uint32(math.MaxUint32)
	for _, key := range keys {
		if !p.banned(key, now) {
			minU = min(minU, p.scores[key])
		}
	}
	w := make(map[string]uint64)
	for _, key := range keys {
		if !p.banned(key, now) {
			delta := p.scores[key] - minU
			if delta <= 10 {
				w[key] = uint64(1) << (10 - delta)
			}
		}
	}
	return w
}
func (p *relayPolicy) choose(keys []string, now time.Time) string {
	sort.Strings(keys)
	w := p.weights(keys, now)
	var total uint64
	for _, weight := range w {
		total += weight
	}
	if total == 0 {
		return ""
	}
	n := p.random.Uint64N(total)
	for _, key := range keys {
		if n < w[key] {
			return key
		}
		n -= w[key]
	}
	return ""
}
func (p *relayPolicy) victim(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	worst := keys[0]
	for _, key := range keys {
		if p.scores[key] > p.scores[worst] {
			worst = key
		}
	}
	if p.scores[worst] > 5 {
		return worst
	}
	return keys[p.random.IntN(len(keys))]
}
