package room

import (
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/envelope"
)

func TestHistoryCountCapEvictsOldest(t *testing.T) {
	h := NewHistory(3, time.Hour)
	for _, s := range []string{"a", "b", "c", "d"} {
		h.Add(Item{Type: "msg", From: s})
	}
	got := h.Recent()
	if len(got) != 3 || got[0].From != "b" || got[2].From != "d" {
		t.Fatalf("want [b c d], got %+v", got)
	}
}

func TestHistoryAgeCapTrimsExpired(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0)
	h := NewHistory(100, time.Minute)
	h.now = func() time.Time { return clk }

	h.Add(Item{Type: "msg", From: "old"})
	clk = clk.Add(2 * time.Minute)
	h.Add(Item{Type: "msg", From: "new"})

	got := h.Recent()
	if len(got) != 1 || got[0].From != "new" {
		t.Fatalf("want [new], got %+v", got)
	}
	if h.Len() != 1 {
		t.Fatalf("expired entry not compacted, len=%d", h.Len())
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

func TestObserveAcceptedMarksPresenceAndStoresByType(t *testing.T) {
	name, err := ParseName("tonnet:room")
	if err != nil {
		t.Fatal(err)
	}
	r := New(name, make([]byte, 32))

	dm := envelope.Envelope{Type: "dm", Nick: "a", Text: "Ym94", TS: 1, Room: "tonnet:room", To: "aa", Key: "k1"}
	r.ObserveAccepted(dm, nil)
	if got := r.Recent(); len(got) != 1 || got[0].Type != "dm" || got[0].To != "aa" || got[0].From != "k1" {
		t.Fatalf("dm must enter the history buffer with routing metadata, got %+v", got)
	}
	if r.PresenceCount() != 1 {
		t.Fatal("an accepted message must create a presence entry")
	}

	hello := envelope.Envelope{Type: "hello", Nick: "b", TS: 2, Room: "tonnet:room", Key: "k2"}
	r.ObserveAccepted(hello, nil)
	if got := r.Recent(); len(got) != 1 {
		t.Fatalf("hello must not enter the history buffer, len=%d", len(got))
	}
	if r.PresenceCount() != 2 {
		t.Fatal("hello must mark presence")
	}

	grant := envelope.Envelope{Type: "cert-grant", Nick: "o", TS: 3, Room: "tonnet:room", To: "k1", Key: "k3"}
	r.ObserveAccepted(grant, nil)
	if got := r.Recent(); len(got) != 1 {
		t.Fatalf("cert-grant must not enter the history buffer, len=%d", len(got))
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
