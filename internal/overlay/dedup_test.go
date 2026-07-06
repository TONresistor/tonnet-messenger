package overlay

import (
	"encoding/binary"
	"testing"
)

func h(i uint64) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b, i)
	return b
}

func TestDedupFirstSightingThenDuplicate(t *testing.T) {
	d := NewDedup(0)
	if d.Seen(h(1)) {
		t.Fatal("first sighting reported as duplicate")
	}
	if !d.Seen(h(1)) {
		t.Fatal("second sighting not reported as duplicate")
	}
	if !d.Contains(h(1)) || d.Contains(h(2)) {
		t.Fatal("membership wrong")
	}
}

func TestDedupEvictsOldestPastCap(t *testing.T) {
	d := NewDedup(3)
	for i := uint64(1); i <= 3; i++ {
		d.Seen(h(i))
	}
	if !d.Seen(h(1)) {
		t.Fatal("h(1) should be a duplicate")
	}
	d.Seen(h(4))
	if d.Len() != 3 {
		t.Fatalf("cap not enforced: len=%d", d.Len())
	}
	if d.Contains(h(2)) {
		t.Fatal("h(2) (LRU) should have been evicted")
	}
	if !d.Contains(h(1)) || !d.Contains(h(3)) || !d.Contains(h(4)) {
		t.Fatal("wrong survivors after eviction")
	}
	if d.Seen(h(2)) {
		t.Fatal("evicted hash should read as new on re-sighting")
	}
}

func TestDedupConcurrentSingleWinner(t *testing.T) {
	d := NewDedup(0)
	const workers = 64
	firsts := make(chan bool, workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func() {
			<-start
			firsts <- d.Seen(h(7))
		}()
	}
	close(start)
	newCount := 0
	for i := 0; i < workers; i++ {
		if !<-firsts {
			newCount++
		}
	}
	if newCount != 1 {
		t.Fatalf("exactly one goroutine must see the hash as new, got %d", newCount)
	}
}

func TestDedupReserveCommitRelease(t *testing.T) {
	d := NewDedup(2)
	id := h(9)

	if !d.Reserve(id) {
		t.Fatal("first reserve should win")
	}
	if d.Reserve(id) {
		t.Fatal("pending id must block duplicate reserves")
	}
	if d.Contains(id) {
		t.Fatal("pending id must not be marked delivered")
	}

	d.Release(id)
	if !d.Reserve(id) {
		t.Fatal("released id should be reservable again")
	}
	d.Commit(id)
	if !d.Contains(id) {
		t.Fatal("committed id must be delivered")
	}
	if d.Reserve(id) {
		t.Fatal("committed id must not be reservable")
	}
	if !d.Seen(id) {
		t.Fatal("committed id must dedup")
	}
}
