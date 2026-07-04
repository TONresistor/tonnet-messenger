package room

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/envelope"
)

func TestHistoryCountCapEvictsOldest(t *testing.T) {
	h := NewHistory(3, time.Hour)
	for _, s := range []string{"a", "b", "c", "d"} {
		h.Add([]byte(s))
	}
	got := h.Recent()
	if len(got) != 3 || string(got[0]) != "b" || string(got[2]) != "d" {
		t.Fatalf("want [b c d], got %q", got)
	}
}

func TestHistoryAgeCapTrimsExpired(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0)
	h := NewHistory(100, time.Minute)
	h.now = func() time.Time { return clk }

	h.Add([]byte("old"))
	clk = clk.Add(2 * time.Minute)
	h.Add([]byte("new"))

	got := h.Recent()
	if len(got) != 1 || string(got[0]) != "new" {
		t.Fatalf("want [new], got %q", got)
	}
	if h.Len() != 1 {
		t.Fatalf("expired entry not compacted, len=%d", h.Len())
	}
}

func TestHistoryCopiesInput(t *testing.T) {
	h := NewHistory(4, time.Hour)
	buf := []byte("hello")
	h.Add(buf)
	copy(buf, "world")
	if got := h.Recent(); string(got[0]) != "hello" {
		t.Fatalf("history did not copy input: %q", got[0])
	}
}

func TestPresenceMarkAndExpire(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0)
	p := NewPresence(30 * time.Second)
	p.now = func() time.Time { return clk }

	p.Mark("kA", "alice")
	p.Mark("kB", "bob")
	if p.Count() != 2 {
		t.Fatalf("want 2 present, got %d", p.Count())
	}

	clk = clk.Add(20 * time.Second)
	p.Mark("kA", "")
	clk = clk.Add(20 * time.Second)
	r := p.Roster()
	if len(r) != 1 || r[0].Key != "kA" || r[0].Nick != "alice" {
		t.Fatalf("want [alice], got %+v", r)
	}
}

func TestPresenceIgnoresBlankKey(t *testing.T) {
	p := NewPresence(time.Minute)
	p.Mark("", "anon")
	if p.Count() != 0 {
		t.Fatal("blank-key (unsigned) peer should not appear on roster")
	}
}

func TestPresenceCapEvictsLeastRecent(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0)
	p := NewPresence(time.Hour)
	p.max = 2
	p.now = func() time.Time { return clk }

	p.Mark("k1", "a")
	clk = clk.Add(time.Second)
	p.Mark("k2", "b")
	clk = clk.Add(time.Second)
	p.Mark("k3", "c")

	r := p.Roster()
	if len(r) != 2 {
		t.Fatalf("cap not enforced: %d entries", len(r))
	}
	for _, m := range r {
		if m.Key == "k1" {
			t.Fatal("least-recently-seen (k1) should have been evicted")
		}
	}
}

func TestPresenceSweepDropsExpired(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0)
	p := NewPresence(30 * time.Second)
	p.now = func() time.Time { return clk }
	p.Mark("k1", "a")
	clk = clk.Add(60 * time.Second)
	p.Sweep()
	if got := len(p.seen); got != 0 {
		t.Fatalf("Sweep should drop expired entries, %d remain", got)
	}
}

func TestObserveOnlyMarksVerifiedPresence(t *testing.T) {
	r := New("room", make([]byte, 32))

	unsigned, _ := json.Marshal(map[string]any{"type": "msg", "nick": "x", "text": "hi", "ts": 1})
	r.Observe(unsigned)
	if r.PresenceCount() != 0 {
		t.Fatal("an unsigned message must not create a presence entry")
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	env := envelope.Envelope{Type: "msg", Nick: "y", Text: "hi", TS: 2}
	if err := env.Sign(priv); err != nil {
		t.Fatal(err)
	}
	signed, _ := env.Marshal()
	r.Observe(signed)
	if r.PresenceCount() != 1 {
		t.Fatal("a validly-signed message must create a presence entry")
	}

	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	forged := envelope.Envelope{Type: "msg", Nick: "z", Text: "orig", TS: 3}
	if err := forged.Sign(priv2); err != nil {
		t.Fatal(err)
	}
	forged.Text = "tampered"
	badBytes, _ := forged.Marshal()
	r.Observe(badBytes)
	if r.PresenceCount() != 1 {
		t.Fatalf("a tampered (bad-signature) message must not create presence, count=%d", r.PresenceCount())
	}
}

func TestObserveStoresDMButNotHello(t *testing.T) {
	r := New("room", make([]byte, 32))

	dm, _ := json.Marshal(map[string]any{"type": "dm", "nick": "a", "text": "Ym94", "ts": 1, "room": "room", "to": "aa"})
	r.Observe(dm)
	if got := r.Recent(); len(got) != 1 {
		t.Fatalf("dm must enter the history buffer, len=%d", len(got))
	}

	hello, _ := json.Marshal(map[string]any{"type": "hello", "nick": "a", "text": "", "ts": 2, "room": "room"})
	r.Observe(hello)
	if got := r.Recent(); len(got) != 1 {
		t.Fatalf("hello must not enter the history buffer, len=%d", len(got))
	}
}

func TestPresenceRosterOrderedByRecency(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0)
	p := NewPresence(time.Hour)
	p.now = func() time.Time { return clk }
	p.Mark("k1", "one")
	clk = clk.Add(time.Second)
	p.Mark("k2", "two")
	r := p.Roster()
	if r[0].Key != "k2" || r[1].Key != "k1" {
		t.Fatalf("roster not most-recent-first: %+v", r)
	}
}
