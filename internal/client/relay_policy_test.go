package client

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

func TestRelayWeightsReplacementAndOutcomeCodes(t *testing.T) {
	p := newRelayPolicy()
	p.random = rand.New(rand.NewPCG(1, 2))
	now := time.Unix(1700000000, 0)
	p.scores = map[string]uint32{"a": 3, "b": 4, "c": 13, "d": 14}
	w := p.weights([]string{"a", "b", "c", "d"}, now)
	if w["a"] != 1024 || w["b"] != 512 || w["c"] != 1 || w["d"] != 0 {
		t.Fatal("wrong TON weights", w)
	}
	if p.victim([]string{"a", "b", "c", "d"}) != "d" {
		t.Fatal("full set did not drop most unreliable above 5")
	}
	p.scores = map[string]uint32{"a": 5, "b": 0}
	expected := rand.New(rand.NewPCG(1, 2))
	want := []string{"a", "b"}[expected.IntN(2)]
	if got := p.victim([]string{"b", "a"}); got != want {
		t.Fatal("u=5 did not use ordinary random replacement", got, want)
	}
	pool := newRelayPool(t.Context(), nil)
	defer pool.Close()
	key := []byte("01234567890123456789012345678901")
	id := string(key)
	pool.policy.scores[id] = 4
	for _, code := range []int32{1, 16, 17} {
		pool.rejected(key, code, now)
		if pool.policy.scores[id] != 4 {
			t.Fatal("unscored rejection changed u", code)
		}
	}
	pool.observe(key, relayTimeout, now)
	pool.observe(key, relayNoAnswer, now)
	pool.observe(key, relayMalformedAnswer, now)
	if pool.policy.scores[id] != 7 {
		t.Fatal("failures not scored +1")
	}
	pool.observe(key, relaySuccess, now) // An empty verified inbox page uses this same outcome.
	if pool.policy.scores[id] != 6 {
		t.Fatal("success did not reduce unreliability")
	}
	for i := 0; i < 8; i++ {
		pool.observe(key, relaySuccess, now)
	}
	if pool.policy.scores[id] != 0 {
		t.Fatal("success underflowed score")
	}
	pool.rejected(key, 20, now)
	if pool.policy.scores[id] != 1 {
		t.Fatal("invalid wire code was not a malformed answer")
	}
	pool.observe(key, relayUnsupported, now)
	if _, ok := pool.policy.scores[id]; ok {
		t.Fatal("unsupported peer retained in relay set")
	}
}

func TestRelayBanEscalationDecayAndExpiry(t *testing.T) {
	p := newRelayPolicy()
	now := time.Unix(1700000000, 0)
	key := "relay"
	p.observe(key, relayInvalidSignature, now)
	if p.bans[key].duration != 90*time.Second || !p.bans[key].until.Equal(now.Add(time.Minute)) || !p.banned(key, now.Add(time.Minute-time.Nanosecond)) || p.banned(key, now.Add(time.Minute)) {
		t.Fatal("initial ban boundary", p.bans[key])
	}
	p.observe(key, relayInvalidSignature, now.Add(time.Minute))
	if p.bans[key].duration != 135*time.Second || !p.bans[key].until.Equal(now.Add(150*time.Second)) {
		t.Fatal("ban forgot duration after expiry")
	}
	until := p.bans[key].until
	p.observe(key, relayValidUnscored, now.Add(70*time.Second))
	if p.bans[key].duration != 90*time.Second || p.bans[key].until != until {
		t.Fatal("valid answer did not decay next duration independently")
	}
	for i := 0; i < 30; i++ {
		p.observe(key, relayInvalidSignature, now.Add(time.Duration(i)*time.Hour))
	}
	if p.bans[key].duration != time.Hour {
		t.Fatal("ban duration cap")
	}
	for i := 0; i < 30; i++ {
		p.observe(key, relaySuccess, now.Add(time.Duration(i)*time.Hour))
	}
	if p.bans[key].duration != time.Minute {
		t.Fatal("ban duration floor")
	}
}

func TestRelayBanTableEvictsLowestDurationThenOldest(t *testing.T) {
	p := newRelayPolicy()
	now := time.Unix(1700000000, 0)
	for i := 0; i < maxRelayBans; i++ {
		key := fmt.Sprintf("%032d", i)
		p.observe(key, relayInvalidSignature, now.Add(time.Duration(i)*time.Second))
	}
	first, second := fmt.Sprintf("%032d", 0), fmt.Sprintf("%032d", 1)
	p.observe(first, relayInvalidSignature, now.Add(5000*time.Second)) // Higher d survives even though it was oldest.
	p.observe("new", relayInvalidSignature, now.Add(5001*time.Second))
	if len(p.bans) != maxRelayBans {
		t.Fatal("unbounded ban table")
	}
	if _, ok := p.bans[first]; !ok {
		t.Fatal("higher duration entry evicted")
	}
	if _, ok := p.bans[second]; ok {
		t.Fatal("oldest tied duration not evicted")
	}
	low := fmt.Sprintf("%032d", 100)
	p.observe(low, relaySuccess, now.Add(5002*time.Second)) // d=60 is now the lowest, despite a recent update.
	p.observe("another", relayInvalidSignature, now.Add(5003*time.Second))
	if _, ok := p.bans[low]; ok {
		t.Fatal("lowest duration did not take eviction priority")
	}
}
