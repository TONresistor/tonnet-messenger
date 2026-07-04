package node

import (
	"bytes"
	"testing"

	"github.com/TONresistor/tonnet-messenger/internal/room"
)

func TestContentIDStableAndDistinct(t *testing.T) {
	a1 := room.RawMessage{Data: []byte(`{"type":"msg","text":"hi"}`)}
	a2 := room.RawMessage{Data: []byte(`{"type":"msg","text":"hi"}`)}
	b := room.RawMessage{Data: []byte(`{"type":"msg","text":"yo"}`)}

	if !bytes.Equal(contentID(a1), contentID(a2)) {
		t.Fatal("identical payloads must share a content id (dedup would miss loops)")
	}
	if bytes.Equal(contentID(a1), contentID(b)) {
		t.Fatal("distinct payloads must have distinct content ids")
	}
	ap := &room.RawMessage{Data: append([]byte(nil), a1.Data...)}
	if !bytes.Equal(contentID(a1), contentID(ap)) {
		t.Fatal("value and pointer RawMessage must yield the same content id")
	}
}

func TestPeerTableLeafVsNodeCounting(t *testing.T) {
	tbl := newPeerTable(0)

	tbl.addInbound("leafA", nil, nil)
	tbl.addInbound("leafB", nil, nil)
	if m, nd := tbl.counts(); m != 0 || nd != 0 {
		t.Fatalf("silent leaves must not count: members=%d nodes=%d", m, nd)
	}
	if !tbl.markMember("leafA") {
		t.Fatal("first overlay msg from leafA should mark it a member")
	}
	if tbl.markMember("leafA") {
		t.Fatal("markMember must be idempotent (no double count / double replay)")
	}
	if m, _ := tbl.counts(); m != 1 {
		t.Fatalf("want 1 member, got %d", m)
	}

	if _, created := tbl.addNode("nodeC", nil, nil, nil); !created {
		t.Fatal("addNode should create nodeC")
	}
	if tbl.markMember("nodeC") {
		t.Fatal("a node peer must never become a leaf member")
	}
	if m, nd := tbl.counts(); m != 1 || nd != 1 {
		t.Fatalf("want members=1 nodes=1, got members=%d nodes=%d", m, nd)
	}
}

func TestInboundNodeReclassifiedNotDoubleCounted(t *testing.T) {
	tbl := newPeerTable(0)

	tbl.addInbound("peerX", nil, nil)
	tbl.markMember("peerX")
	if m, _ := tbl.counts(); m != 1 {
		t.Fatalf("precondition: peerX counted as member, got %d", m)
	}

	tbl.setSigned("peerX", nil)
	if m, nd := tbl.counts(); m != 0 || nd != 1 {
		t.Fatalf("after reclassify want members=0 nodes=1, got members=%d nodes=%d", m, nd)
	}

	if _, created := tbl.addNode("peerX", nil, nil, nil); created {
		t.Fatal("addNode must reuse the existing inbound entry (no duplicate connection slot)")
	}
}

func TestLeafCapRefusesButNodesBypass(t *testing.T) {
	tbl := newPeerTable(2)
	if p, added := tbl.addInbound("l1", nil, nil); p == nil || !added {
		t.Fatal("first leaf should be admitted")
	}
	if p, added := tbl.addInbound("l2", nil, nil); p == nil || !added {
		t.Fatal("second leaf should be admitted")
	}
	if p, added := tbl.addInbound("l3", nil, nil); p != nil || added {
		t.Fatal("leaf past the cap must be refused as (nil, false) so onInbound closes it")
	}
	tbl.markKnown("nodeX")
	if p, added := tbl.addInbound("nodeX", nil, nil); p == nil || !added {
		t.Fatal("a known node must be admitted despite the leaf cap")
	}
}

func TestRateLimiterBlocksBurst(t *testing.T) {
	b := newTokenBucket(3, 0)
	got := 0
	for i := 0; i < 10; i++ {
		if b.allow() {
			got++
		}
	}
	if got != 3 {
		t.Fatalf("token bucket should allow exactly the burst (3), allowed %d", got)
	}
}

func TestRelayTargetsExcludeSenderAndSilentLeaves(t *testing.T) {
	tbl := newPeerTable(0)
	tbl.addInbound("a", nil, nil)
	tbl.addInbound("b", nil, nil)
	tbl.addInbound("silent", nil, nil)
	tbl.addNode("c", nil, nil, nil)
	tbl.markMember("a")
	tbl.markMember("b")

	got := map[string]bool{}
	for _, p := range tbl.relayTargets("a") {
		got[p.id] = true
	}
	if got["a"] {
		t.Fatal("the sender must be excluded from the fan-out set")
	}
	if got["silent"] {
		t.Fatal("non-member leaves (e.g. transient DHT peers) must be excluded")
	}
	if !got["b"] || !got["c"] {
		t.Fatalf("fan-out must include member leaves and node peers, got %v", got)
	}
}
