package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/keys"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/envelope"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/room"
	"github.com/TONresistor/tonnet-messenger/internal/tonproof"
)

func genKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func newTestNode(t *testing.T, roomName string) *Node {
	t.Helper()
	name, err := room.ParseName(roomName)
	if err != nil {
		t.Fatal(err)
	}
	oid := make([]byte, 32)
	return &Node{
		cfg:         Config{Room: roomName, OverlayID: oid},
		name:        name,
		room:        room.New(name, oid),
		peers:       newPeerTable(0),
		dedup:       ov.NewDedup(deliveredCap),
		penalties:   newPenaltyBox(),
		sources:     newSourceLimits(),
		uncertified: newTokenBucket(uncertifiedBurst, uncertifiedRefill),
		certs:       newCertCache(),
		devices:     newDeviceTable(),
		wrappers:    newWrapperStore(),
	}
}

func provenEnvelope(t *testing.T, devPriv, walletPriv ed25519.PrivateKey, roomName, typ, text, to string) envelope.Envelope {
	t.Helper()
	devPub := devPriv.Public().(ed25519.PublicKey)
	walletPub := walletPriv.Public().(ed25519.PublicKey)
	now := time.Now().Unix()
	wexp := now + 3600

	env := envelope.Envelope{
		Type: typ, Nick: "t", Text: text,
		TS: now * 1000, Room: roomName, To: to,
		WKey: hex.EncodeToString(walletPub),
		WTS:  now, WExp: wexp,
	}
	addr, err := tonproof.WalletAddress(walletPub)
	if err != nil {
		t.Fatal(err)
	}
	d := tonproof.Digest(addr, now, tonproof.Payload(hex.EncodeToString(devPub), wexp))
	env.WSig = hex.EncodeToString(ed25519.Sign(walletPriv, d))
	if err := env.Sign(devPriv); err != nil {
		t.Fatal(err)
	}
	return env
}

func wrap(t *testing.T, devPriv ed25519.PrivateKey, cert any, env envelope.Envelope, date int64) broadcast.Broadcast {
	t.Helper()
	body, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b, err := broadcast.Sign(devPriv, cert, body, date)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func issueCert(t *testing.T, owner ed25519.PrivateKey, overlayID []byte, devPub ed25519.PublicKey) tonoverlay.Certificate {
	t.Helper()
	devID, err := broadcast.KeyID(devPub)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := room.IssueCertificate(owner, overlayID, devID, broadcast.MaxSize, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func leafPeer(n *Node, id string) *peer {
	p, _, _ := n.peers.addInbound(id, nil, nil)
	return p
}

func detachedPeer(id string) *peer {
	return newPeer(id, kindLeaf, nil, nil, nil)
}

func TestAdmitAcceptsProvenAndDedups(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	dev, wallet := genKey(t), genKey(t)
	env := provenEnvelope(t, dev, wallet, "tonnet:test", "msg", "hi", "")
	b := wrap(t, dev, nil, env, time.Now().Unix())
	p := leafPeer(n, "leafA")

	gotEnv, _, ok := n.admit(p, b, time.Now())
	if !ok {
		t.Fatal("a proven fresh broadcast must be accepted")
	}
	if gotEnv.Key != env.Key {
		t.Fatal("accepted envelope key mismatch")
	}
	if n.room.PresenceCount() != 1 {
		t.Fatal("accepted message must mark presence")
	}
	if len(n.room.Recent()) != 1 {
		t.Fatal("accepted msg must enter history")
	}
	if id, err := b.ID(); err != nil {
		t.Fatal(err)
	} else if _, stored := n.wrappers.get(id); !stored {
		t.Fatal("accepted wrapper must be stored for pull-repair")
	}

	if _, _, ok := n.admit(p, b, time.Now()); ok {
		t.Fatal("the same broadcast id must dedup")
	}
}

func TestAdmitConcurrentDuplicateSingleAccept(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	dev, wallet := genKey(t), genKey(t)
	env := provenEnvelope(t, dev, wallet, "tonnet:test", "msg", "hi", "")
	b := wrap(t, dev, nil, env, time.Now().Unix())
	p := leafPeer(n, "leafA")

	const workers = 32
	start := make(chan struct{})
	results := make(chan bool, workers)
	now := time.Now()
	for i := 0; i < workers; i++ {
		go func() {
			<-start
			_, _, ok := n.admit(p, b, now)
			results <- ok
		}()
	}
	close(start)

	accepted := 0
	for i := 0; i < workers; i++ {
		if <-results {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("exactly one concurrent duplicate must be accepted, got %d", accepted)
	}
	if len(n.room.Recent()) != 1 {
		t.Fatal("concurrent duplicates must store one history item")
	}
}

func TestAdmitRejectsStaleAndFutureDates(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	dev, wallet := genKey(t), genKey(t)
	env := provenEnvelope(t, dev, wallet, "tonnet:test", "msg", "old", "")
	p := leafPeer(n, "leafA")

	stale := wrap(t, dev, nil, env, time.Now().Add(-2*time.Minute).Unix())
	if _, _, ok := n.admit(p, stale, time.Now()); ok {
		t.Fatal("a broadcast older than the freshness window must be dropped")
	}
	future := wrap(t, dev, nil, env, time.Now().Add(2*time.Minute).Unix())
	if _, _, ok := n.admit(p, future, time.Now()); ok {
		t.Fatal("a broadcast dated in the future must be dropped")
	}
}

func TestAdmitRejectsWrongRoom(t *testing.T) {
	n := newTestNode(t, "tonnet:roomA")
	dev, wallet := genKey(t), genKey(t)
	env := provenEnvelope(t, dev, wallet, "tonnet:roomB", "msg", "cross", "")
	b := wrap(t, dev, nil, env, time.Now().Unix())
	p := leafPeer(n, "leafA")

	if _, _, ok := n.admit(p, b, time.Now()); ok {
		t.Fatal("an envelope for another room must never be accepted (cross-room injection)")
	}
	if len(n.room.Recent()) != 0 {
		t.Fatal("cross-room envelope must not enter history")
	}
}

func TestAdmitRejectsSrcMismatchAndPenalizes(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	dev, wallet, mallory := genKey(t), genKey(t), genKey(t)
	env := provenEnvelope(t, dev, wallet, "tonnet:test", "msg", "steal", "")
	body, _ := env.Marshal()
	b, err := broadcast.Sign(mallory, nil, body, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	p := leafPeer(n, "leafM")

	if _, _, ok := n.admit(p, b, time.Now()); ok {
		t.Fatal("wrapper source != envelope key must be rejected (proxy replay)")
	}
	if !n.penalties.banned("leafM", time.Now()) {
		t.Fatal("src mismatch must trigger the signature penalty")
	}
}

func TestAdmitDeviceOnlyAcceptedInOpenRoom(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	dev := genKey(t)
	env := envelope.Envelope{Type: "msg", Nick: "x", Text: "no wallet needed", TS: time.Now().UnixMilli(), Room: "tonnet:test"}
	if err := env.Sign(dev); err != nil {
		t.Fatal(err)
	}
	b := wrap(t, dev, nil, env, time.Now().Unix())
	p := leafPeer(n, "leafA")

	if _, _, ok := n.admit(p, b, time.Now()); !ok {
		t.Fatal("an open room must accept a device-signed message with no wallet proof (blockchain-agnostic core)")
	}
	if n.room.PresenceCount() != 1 {
		t.Fatal("device-only message must mark presence")
	}
	if len(n.room.Recent()) != 1 {
		t.Fatal("device-only message must enter history")
	}
}

func TestGatedRoomAcceptsDeviceOnlyWithOwnerCert(t *testing.T) {
	owner := genKey(t)
	ownerHex := hex.EncodeToString(owner.Public().(ed25519.PublicKey))
	roomName := "tonnet:private#o=" + ownerHex
	n := newTestNode(t, roomName)
	dev := genKey(t)
	p := leafPeer(n, "leafA")

	env := envelope.Envelope{Type: "msg", Nick: "m", Text: "certified, no wallet", TS: time.Now().UnixMilli(), Room: roomName}
	if err := env.Sign(dev); err != nil {
		t.Fatal(err)
	}
	cert := issueCert(t, owner, n.cfg.OverlayID, dev.Public().(ed25519.PublicKey))
	b := wrap(t, dev, cert, env, time.Now().Unix())

	if _, _, ok := n.admit(p, b, time.Now()); !ok {
		t.Fatal("a gated room must accept an owner-certified device-only message (no wallet proof required)")
	}
}

func TestGatedRoomRequiresOwnerCert(t *testing.T) {
	owner := genKey(t)
	ownerHex := hex.EncodeToString(owner.Public().(ed25519.PublicKey))
	roomName := "tonnet:private#o=" + ownerHex
	n := newTestNode(t, roomName)
	dev, wallet := genKey(t), genKey(t)
	devPub := dev.Public().(ed25519.PublicKey)
	p := leafPeer(n, "leafA")

	env := provenEnvelope(t, dev, wallet, roomName, "msg", "hi", "")
	noCert := wrap(t, dev, nil, env, time.Now().Unix())
	if _, _, ok := n.admit(p, noCert, time.Now()); ok {
		t.Fatal("gated room must reject uncertified posts")
	}

	rogue := genKey(t)
	rogueCert := issueCert(t, rogue, n.cfg.OverlayID, devPub)
	badIssuer := wrap(t, dev, rogueCert, env, time.Now().Unix())
	if _, _, ok := n.admit(p, badIssuer, time.Now()); ok {
		t.Fatal("a certificate from a non-owner issuer must be rejected")
	}

	cert := issueCert(t, owner, n.cfg.OverlayID, devPub)
	good := wrap(t, dev, cert, env, time.Now().Unix())
	if _, _, ok := n.admit(p, good, time.Now()); !ok {
		t.Fatal("an owner-certified post must be accepted")
	}

	other := genKey(t)
	stolen := issueCert(t, owner, n.cfg.OverlayID, other.Public().(ed25519.PublicKey))
	env2 := provenEnvelope(t, dev, wallet, roomName, "msg", "hi2", "")
	graft := wrap(t, dev, stolen, env2, time.Now().Unix())
	if _, _, ok := n.admit(p, graft, time.Now()); ok {
		t.Fatal("a certificate issued to another device key must not authorize this sender")
	}
}

func TestGatedRoomCertReqBudget(t *testing.T) {
	owner := genKey(t)
	ownerHex := hex.EncodeToString(owner.Public().(ed25519.PublicKey))
	roomName := "tonnet:private#o=" + ownerHex
	n := newTestNode(t, roomName)
	p := leafPeer(n, "leafA")

	accepted := 0
	for i := 0; i < uncertifiedBurst+4; i++ {
		dev, wallet := genKey(t), genKey(t)
		env := provenEnvelope(t, dev, wallet, roomName, "cert-req", "", "")
		b := wrap(t, dev, nil, env, time.Now().Unix())
		if _, _, ok := n.admit(p, b, time.Now()); ok {
			accepted++
		}
	}
	if accepted != uncertifiedBurst {
		t.Fatalf("cert-req must be admitted uncertified within the budget only: got %d, want %d", accepted, uncertifiedBurst)
	}
}

func TestSelectTargetsRoutesAddressedTypes(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	now := time.Now()

	recipient := leafPeer(n, "leafR")
	_ = recipient
	n.peers.markMember("leafR")
	leafPeer(n, "leafB")
	n.peers.markMember("leafB")
	n.peers.addNode("nodeC", nil, nil, nil)
	n.peers.markGood("nodeC", now)
	n.devices.bind("recipientKey", "leafR", now)

	dm := envelope.Envelope{Type: "dm", To: "recipientKey"}
	got := map[string]bool{}
	for _, p := range n.selectTargets("leafS", dm, now) {
		got[p.id] = true
	}
	if !got["leafR"] || !got["nodeC"] {
		t.Fatalf("dm must reach the bound recipient leaf and node peers, got %v", got)
	}
	if got["leafB"] {
		t.Fatal("dm must not fan out to unrelated leaves")
	}

	msg := envelope.Envelope{Type: "msg"}
	got = map[string]bool{}
	for _, p := range n.selectTargets("leafS", msg, now) {
		got[p.id] = true
	}
	if !got["leafR"] || !got["leafB"] || !got["nodeC"] {
		t.Fatalf("room messages must reach all member leaves and node peers, got %v", got)
	}
}

func TestSelectTargetsBoundsNodeFanout(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	for i := 0; i < 9; i++ {
		id := string(rune('a' + i))
		n.peers.addNode(id, nil, nil, nil)
		n.peers.markGood(id, time.Now())
	}
	msg := envelope.Envelope{Type: "msg"}
	if got := len(n.selectTargets("x", msg, time.Now())); got != nodeFanout {
		t.Fatalf("node fan-out must be bounded to %d, got %d", nodeFanout, got)
	}
}

func TestReplayItemsFiltersDMs(t *testing.T) {
	obj := broadcast.Broadcast{}
	items := []room.Item{
		{Type: "msg", From: "a", Obj: obj},
		{Type: "dm", From: "a", To: "x", Obj: obj},
		{Type: "dm", From: "y", To: "a", Obj: obj},
		{Type: "dm", From: "b", To: "c", Obj: obj},
	}

	if got := len(replayItems(items, "")); got != 1 {
		t.Fatalf("unknown leaf key must only replay public messages, got %d", got)
	}
	if got := len(replayItems(items, "a")); got != 3 {
		t.Fatalf("leaf a must get its msg + sent/received dms, got %d", got)
	}
	if got := len(replayItems(items, "c")); got != 2 {
		t.Fatalf("leaf c must get public msg + its dm, got %d", got)
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

func TestInboundLeafReconnectCreatesFreshSession(t *testing.T) {
	tbl := newPeerTable(0)
	raw1 := &recordingPeer{id: []byte("leaf")}
	first, added, replaced := tbl.addInbound("leaf", nil, raw1)
	if first == nil || !added {
		t.Fatal("first leaf session should be added")
	}
	if replaced != nil {
		t.Fatal("first leaf session must not replace another session")
	}
	if !tbl.markMember("leaf") || !tbl.markReplayed("leaf") {
		t.Fatal("first leaf session should join and receive replay once")
	}

	raw2 := &recordingPeer{id: []byte("leaf")}
	second, added, replaced := tbl.addInbound("leaf", nil, raw2)
	if second == nil || !added {
		t.Fatal("a new transport for the same leaf must create a fresh session")
	}
	if replaced != first {
		t.Fatal("the stale session must be returned for cleanup")
	}
	if second == first || second.raw != raw2 {
		t.Fatal("the fresh session must replace the stale transport")
	}
	if !tbl.markReplayed("leaf") {
		t.Fatal("the reconnected leaf must receive replay once")
	}
	if tbl.markReplayed("leaf") {
		t.Fatal("replay must remain limited to once per connection")
	}
}

func TestInvalidCustomMessageDoesNotPromoteLeaf(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	p := leafPeer(n, "leafBad")

	n.handleCustomMessage(p, tl.Raw([]byte{0x01, 0x02}), time.Now())

	if members, _ := n.peers.counts(); members != 0 {
		t.Fatalf("invalid custom message must not create a member, got %d", members)
	}
	if len(n.room.Recent()) != 0 {
		t.Fatal("invalid custom message must not enter history")
	}
}

func TestUnknownInboundInvalidCustomIsNotTracked(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	p := detachedPeer("adnlNoise")

	n.handleCustomMessage(p, tl.Raw([]byte{0x01, 0x02}), time.Now())

	if _, ok := n.peers.get("adnlNoise"); ok {
		t.Fatal("unknown ADNL peer must not be tracked before a valid Tonnet broadcast")
	}
	if evicted := n.peers.evictStale(time.Now().Add(peerQuarantineTTL + time.Second)); len(evicted) != 0 {
		t.Fatalf("untracked ADNL noise must not produce quarantine evictions, got %+v", evicted)
	}
}

func TestAcceptedHelloPromotesLeafOutOfQuarantine(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	dev := genKey(t)
	env := envelope.Envelope{Type: "hello", Nick: "leaf", TS: time.Now().UnixMilli(), Room: "tonnet:test"}
	if err := env.Sign(dev); err != nil {
		t.Fatal(err)
	}
	b := wrap(t, dev, nil, env, time.Now().Unix())
	p := leafPeer(n, "leafA")

	n.handleCustomMessage(p, b, time.Now())

	if members, _ := n.peers.counts(); members != 1 {
		t.Fatalf("accepted hello must create one member, got %d", members)
	}
	got, ok := n.peers.get("leafA")
	if !ok {
		t.Fatal("accepted hello must keep leaf in the table")
	}
	if got.state != peerHealthy {
		t.Fatalf("accepted hello must promote leaf, got state=%v", got.state)
	}
}

func TestUnknownInboundAcceptedHelloTracksMember(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	dev := genKey(t)
	env := envelope.Envelope{Type: "hello", Nick: "leaf", TS: time.Now().UnixMilli(), Room: "tonnet:test"}
	if err := env.Sign(dev); err != nil {
		t.Fatal(err)
	}
	b := wrap(t, dev, nil, env, time.Now().Unix())
	raw := detachedPeer("leafA")
	p, added, _ := n.peers.addInbound(raw.id, raw.w, raw.raw)
	if p == nil || !added {
		t.Fatal("first Tonnet frame must reserve a pending peer slot")
	}

	n.handleCustomMessage(p, b, time.Now())

	got, ok := n.peers.get("leafA")
	if !ok {
		t.Fatal("valid Tonnet broadcast must track the inbound peer")
	}
	if !got.member || got.state != peerHealthy {
		t.Fatalf("accepted peer must be a healthy member, got member=%v state=%v", got.member, got.state)
	}
	if members, _ := n.peers.counts(); members != 1 {
		t.Fatalf("accepted peer must count as one member, got %d", members)
	}
}

func TestUnknownInboundLeafCapRefusesWithoutCommit(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	n.peers = newPeerTable(1)
	leafPeer(n, "leafFull")
	n.peers.markMember("leafFull")

	dev := genKey(t)
	env := envelope.Envelope{Type: "hello", Nick: "leaf", TS: time.Now().UnixMilli(), Room: "tonnet:test"}
	if err := env.Sign(dev); err != nil {
		t.Fatal(err)
	}
	b := wrap(t, dev, nil, env, time.Now().Unix())

	n.handleCustomMessage(detachedPeer("leafOverflow"), b, time.Now())

	if _, ok := n.peers.get("leafOverflow"); ok {
		t.Fatal("overflow leaf must not be tracked")
	}
	if len(n.room.Recent()) != 0 {
		t.Fatal("overflow leaf message must not enter history")
	}
}

func TestNodeOnlyGoodSignalDoesNotPromoteLeaf(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	leafPeer(n, "leafQ")

	if n.peers.markNodeGood("leafQ", time.Now()) {
		t.Fatal("node-only liveness must not promote a leaf")
	}
	got, ok := n.peers.get("leafQ")
	if !ok {
		t.Fatal("leaf must remain in the table")
	}
	if got.state != peerQuarantine {
		t.Fatalf("leaf must remain quarantined, got state=%v", got.state)
	}
}

func TestNodePeerGetsAggregateTrafficBudget(t *testing.T) {
	tbl := newPeerTable(0)
	leaf, _, _ := tbl.addInbound("leaf", nil, nil)
	nodePeer, _ := tbl.addNode("node", nil, nil, nil)

	for i := 0; i < leafPeerBurst; i++ {
		if !leaf.allowIngress() {
			t.Fatalf("leaf token %d should be available", i)
		}
	}
	if leaf.allowIngress() {
		t.Fatal("leaf must stop at its strict burst")
	}
	for i := 0; i < leafPeerBurst+1; i++ {
		if !nodePeer.allowIngress() {
			t.Fatalf("node peer must absorb aggregate burst at token %d", i)
		}
	}
}

func TestPeerLimiterUpgradeIsSynchronized(t *testing.T) {
	tbl := newPeerTable(0)
	p, added, _ := tbl.addInbound("upgrade", nil, nil)
	if p == nil || !added {
		t.Fatal("leaf should be admitted before limiter upgrade")
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1_000; i++ {
			p.allowIngress()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1_000; i++ {
			tbl.setSigned("upgrade", nil)
		}
	}()
	wg.Wait()
}

func TestNodeMetadataRefreshDoesNotRefillLimiter(t *testing.T) {
	tests := []struct {
		name    string
		refresh func(*peerTable)
	}{
		{
			name: "signed record",
			refresh: func(tbl *peerTable) {
				tbl.setSigned("node", nil)
			},
		},
		{
			name: "existing node connection",
			refresh: func(tbl *peerTable) {
				tbl.addNode("node", nil, nil, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tbl := newPeerTable(0)
			p, added := tbl.addNode("node", nil, nil, nil)
			if p == nil || !added {
				t.Fatal("node should be admitted")
			}

			p.limiterMu.RLock()
			limiter := p.limiter
			p.limiterMu.RUnlock()
			limiter.mu.Lock()
			limiter.refillPerSec = 0
			limiter.mu.Unlock()
			for i := 0; i < nodePeerBurst; i++ {
				if !p.allowIngress() {
					t.Fatalf("node token %d should be available", i)
				}
			}
			if p.allowIngress() {
				t.Fatal("precondition: node limiter should be exhausted")
			}

			tt.refresh(tbl)

			p.limiterMu.RLock()
			refreshed := p.limiter
			p.limiterMu.RUnlock()
			if refreshed != limiter {
				t.Fatal("metadata refresh replaced and refilled the node limiter")
			}
			if p.allowIngress() {
				t.Fatal("metadata refresh refilled an exhausted node limiter")
			}
		})
	}
}

func TestQuarantinedNodeIsNotRelayTarget(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	n.peers.addNode("nodeQ", nil, nil, nil)

	if got := n.selectTargets("leafS", envelope.Envelope{Type: "msg"}, time.Now()); len(got) != 0 {
		t.Fatalf("quarantined node must not receive relays, got %d targets", len(got))
	}

	n.peers.markGood("nodeQ", time.Now())
	if got := n.selectTargets("leafS", envelope.Envelope{Type: "msg"}, time.Now()); len(got) != 1 || got[0].id != "nodeQ" {
		t.Fatalf("healthy node must receive relays, got %+v", got)
	}
}

func TestKeepaliveOnlyTargetsHealthyNodes(t *testing.T) {
	tbl := newPeerTable(0)
	now := time.Now()
	tbl.addNode("nodeQ", nil, nil, nil)

	if got := tbl.nodePeersIdleSince(now.Add(peerKeepaliveIdle+time.Second), peerKeepaliveIdle); len(got) != 0 {
		t.Fatalf("quarantined node must not be selected for keepalive, got %d", len(got))
	}

	tbl.markNodeGood("nodeQ", now)
	got := tbl.nodePeersIdleSince(now.Add(peerKeepaliveIdle+time.Second), peerKeepaliveIdle)
	if len(got) != 1 || got[0].id != "nodeQ" {
		t.Fatalf("healthy idle node must be selected for keepalive, got %+v", got)
	}
}

func TestPeerBadScoreEvictsRepeatedSignatureFailures(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	p := leafPeer(n, "leafBad")
	now := time.Now()

	n.punish(p, now)
	if _, ok := n.peers.get("leafBad"); !ok {
		t.Fatal("first signature failure should warn, not evict")
	}
	n.punish(p, now.Add(time.Second))
	if _, ok := n.peers.get("leafBad"); ok {
		t.Fatal("repeated signature failures should evict the peer")
	}
}

func TestPeerTableEvictsStaleQuarantineLeaves(t *testing.T) {
	tbl := newPeerTable(0)
	tbl.addInbound("silent", nil, nil)

	evicted := tbl.evictStale(time.Now().Add(peerQuarantineTTL + time.Second))
	if len(evicted) != 1 || evicted[0].id != "silent" {
		t.Fatalf("stale silent leaf must be evicted, got %+v", evicted)
	}
	if _, ok := tbl.get("silent"); ok {
		t.Fatal("stale leaf must be removed from the table")
	}
}

func TestPeerTableEvictsMemberWithoutAcceptedApplicationTraffic(t *testing.T) {
	tbl := newPeerTable(0)
	now := time.Now()
	tbl.addInbound("idle-member", nil, nil)
	if !tbl.markAccepted("idle-member", now) {
		t.Fatal("member should be accepted")
	}

	// Invalid or transport-only activity may update diagnostics, but must not
	// preserve an application membership slot.
	tbl.markBad("idle-member", 1, now.Add(peerMemberIdleTTL-time.Second))
	evicted := tbl.evictStale(now.Add(peerMemberIdleTTL + time.Second))
	if len(evicted) != 1 || evicted[0].id != "idle-member" {
		t.Fatalf("idle member must be evicted, got %+v", evicted)
	}
}

func TestWrongRoomFramesPenalizeAndEvictPeer(t *testing.T) {
	n := newTestNode(t, "tonnet:test")
	p := leafPeer(n, "wrongRoom")
	dev := genKey(t)
	env := envelope.Envelope{Type: "msg", Nick: "leaf", Text: "noise", TS: time.Now().UnixMilli(), Room: "tonnet:other"}
	if err := env.Sign(dev); err != nil {
		t.Fatal(err)
	}
	b := wrap(t, dev, nil, env, time.Now().Unix())
	now := time.Now()

	n.handleCustomMessage(p, b, now)
	if _, ok := n.peers.get(p.id); !ok {
		t.Fatal("first authenticated policy violation should warn, not evict")
	}
	n.handleCustomMessage(p, b, now.Add(sigPenalty+time.Second))
	if _, ok := n.peers.get(p.id); ok {
		t.Fatal("repeated authenticated wrong-room frames must evict the peer")
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
	p1, added, _ := tbl.addInbound("l1", nil, nil)
	if p1 == nil || !added {
		t.Fatal("first leaf should be admitted")
	}
	p2, added, _ := tbl.addInbound("l2", nil, nil)
	if p2 == nil || !added {
		t.Fatal("second leaf should be admitted")
	}
	p3, added, _ := tbl.addInbound("l3", nil, nil)
	if p3 == nil || !added {
		t.Fatal("pending peers use their own cap and must not consume member slots")
	}
	if _, _, ok := tbl.acceptInbound(p1, time.Now()); !ok {
		t.Fatal("first member should be accepted")
	}
	if _, _, ok := tbl.acceptInbound(p2, time.Now()); !ok {
		t.Fatal("second member should be accepted")
	}
	if _, _, ok := tbl.acceptInbound(p3, time.Now()); ok {
		t.Fatal("third accepted member must be refused at the member cap")
	}
	tbl.markKnown("nodeX")
	if p, added, _ := tbl.addInbound("nodeX", nil, nil); p == nil || !added {
		t.Fatal("a known node must be admitted despite the leaf cap")
	}
}

func TestDisconnectedPendingPeerCannotBeReinsertedByLateAdmission(t *testing.T) {
	tbl := newPeerTable(2)
	p, added, _ := tbl.addInbound("late", nil, nil)
	if p == nil || !added {
		t.Fatal("pending peer should be admitted")
	}
	if !tbl.removePeer("late", p) {
		t.Fatal("pending peer should be removable")
	}
	if _, _, ok := tbl.acceptInbound(p, time.Now()); ok {
		t.Fatal("late verification must not reinsert a disconnected peer")
	}
	if tbl.has("late") {
		t.Fatal("disconnected peer became a ghost member")
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

func TestGlobalIngressLimiterChargesMessagesAndBytesAtomically(t *testing.T) {
	l := newDualLimiter()
	l.messages = 1
	l.bytes = 10
	l.messageRefill = 0
	l.byteRefill = 0
	now := time.Now()
	if l.allow(11, now) {
		t.Fatal("oversized charge must fail")
	}
	if !l.allow(10, now) {
		t.Fatal("failed byte charge must not consume the message token")
	}
	if l.allow(1, now) {
		t.Fatal("message token must be consumed after acceptance")
	}
}

func TestPendingPeerCapIsSeparateFromMemberCap(t *testing.T) {
	tbl := newPeerTable(1)
	for i := 0; i < MaxPendingPeers; i++ {
		if p, added, _ := tbl.addInbound(fmt.Sprintf("pending-%d", i), nil, nil); p == nil || !added {
			t.Fatalf("pending peer %d should fit", i)
		}
	}
	if p, added, _ := tbl.addInbound("overflow", nil, nil); p != nil || added {
		t.Fatal("pending peer past the cap must be refused")
	}
}

func TestSourceLimitsCapsBytes(t *testing.T) {
	s := newSourceLimits()
	now := time.Now()
	if !s.allow("k", sourceBytesPerMinute-100, now) {
		t.Fatal("first message within byte budget must pass")
	}
	if s.allow("k", 200, now) {
		t.Fatal("byte budget exceeded must be rejected")
	}
	if !s.allow("other", 200, now) {
		t.Fatal("another source must have its own budget")
	}
}

func TestCertCacheEvictsAndLimitsMisses(t *testing.T) {
	c := newCertCache()
	c.put("a", certEntry{expireAt: 1, maxSize: 2})
	if e, ok := c.get("a"); !ok || e.expireAt != 1 {
		t.Fatal("cache must return stored entries")
	}
	for i := 0; i < certCacheCap+8; i++ {
		c.put(fmt.Sprintf("k%d", i), certEntry{})
	}
	if _, ok := c.get("a"); ok {
		t.Fatal("oldest entry must be evicted past the cap")
	}
}

func TestDeviceTableTTL(t *testing.T) {
	d := newDeviceTable()
	now := time.Now()
	d.bind("k", "peer1", now)
	if id, ok := d.lookup("k", now); !ok || id != "peer1" {
		t.Fatal("fresh binding must resolve")
	}
	if _, ok := d.lookup("k", now.Add(deviceBindTTL+time.Second)); ok {
		t.Fatal("expired binding must not resolve")
	}
}

func TestDeviceTableSupportsMultiplePeersAndDisconnectCleanup(t *testing.T) {
	d := newDeviceTable()
	now := time.Now()
	d.bind("k", "peer1", now)
	d.bind("k", "peer2", now)
	if got := d.lookupAll("k", now); len(got) != 2 {
		t.Fatalf("want two device bindings, got %v", got)
	}
	d.removePeer("peer1")
	got := d.lookupAll("k", now)
	if len(got) != 1 || got[0] != "peer2" {
		t.Fatalf("disconnect cleanup left %v", got)
	}
}

func TestDeviceBindingRequiresConnectionChallenge(t *testing.T) {
	tbl := newPeerTable(2)
	p, added, _ := tbl.addInbound("leaf", nil, nil)
	if p == nil || !added {
		t.Fatal("leaf should be pending")
	}
	nonce := make([]byte, 32)
	nonce[0] = 0x42
	now := time.Now()
	if !tbl.setChallenge(p, nonce, now.Add(time.Minute)) {
		t.Fatal("challenge should attach to the pending peer")
	}
	if _, _, ok := tbl.acceptInbound(p, now); !ok {
		t.Fatal("valid first frame should admit the peer")
	}
	key := hex.EncodeToString(genKey(t).Public().(ed25519.PublicKey))
	if tbl.authenticateDevice(p, key, "", true, now) {
		t.Fatal("a signed frame without the connection challenge must not bind")
	}
	if !tbl.authenticateDevice(p, key, hex.EncodeToString(nonce), true, now) {
		t.Fatal("the current signed connection challenge must bind")
	}
	if !tbl.authenticateDevice(p, key, "", false, now.Add(time.Second)) {
		t.Fatal("later frames from the authenticated device must refresh its binding")
	}
	other := hex.EncodeToString(genKey(t).Public().(ed25519.PublicKey))
	if tbl.authenticateDevice(p, other, hex.EncodeToString(nonce), true, now) {
		t.Fatal("one connection must not switch to another device key")
	}
}

func TestPenaltyBoxExpires(t *testing.T) {
	b := newPenaltyBox()
	now := time.Now()
	b.punish("p", now)
	if !b.banned("p", now.Add(time.Second)) {
		t.Fatal("penalized peer must be banned inside the window")
	}
	if b.banned("p", now.Add(sigPenalty+time.Second)) {
		t.Fatal("penalty must expire")
	}
}

func TestBroadcastTLRegistered(t *testing.T) {
	dev := genKey(t)
	b, err := broadcast.Sign(dev, tonoverlay.CertificateEmpty{}, []byte("x"), 1)
	if err != nil {
		t.Fatal(err)
	}
	ser, err := tl.Serialize(b, true)
	if err != nil {
		t.Fatal(err)
	}
	var parsed any
	if _, err := tl.Parse(&parsed, ser, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(broadcast.Broadcast); !ok {
		t.Fatalf("wire roundtrip parsed to %T", parsed)
	}
	if _, err := keys.SharedKey(dev, dev.Public().(ed25519.PublicKey)); err != nil {
		t.Skip("shared key sanity only")
	}
}
