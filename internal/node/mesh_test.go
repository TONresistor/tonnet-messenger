package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	p, _ := n.peers.addInbound(id, nil, nil)
	return p
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
		n.peers.addNode(string(rune('a'+i)), nil, nil, nil)
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
