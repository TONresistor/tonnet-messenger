package broadcast

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/keys"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestSignVerifyRoundtrip(t *testing.T) {
	priv := testKey(t)
	b, err := Sign(priv, nil, []byte(`{"type":"msg"}`), 1751700000)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(); err != nil {
		t.Fatalf("fresh broadcast must verify: %v", err)
	}
	if _, ok := b.Certificate.(tonoverlay.CertificateEmpty); !ok {
		t.Fatalf("nil cert must serialize as emptyCertificate, got %T", b.Certificate)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	priv := testKey(t)
	b, err := Sign(priv, nil, []byte("payload"), 1751700000)
	if err != nil {
		t.Fatal(err)
	}

	tampered := b
	tampered.Data = []byte("payloae")
	if tampered.Verify() == nil {
		t.Fatal("modified data must not verify")
	}

	redated := b
	redated.Date++
	if redated.Verify() == nil {
		t.Fatal("modified date must not verify (date is signed)")
	}

	otherPub := testKey(t).Public().(ed25519.PublicKey)
	swapped := b
	swapped.Src = keys.PublicKeyED25519{Key: otherPub}
	if swapped.Verify() == nil {
		t.Fatal("swapped source must not verify")
	}

	flagged := b
	flagged.Flags = 1
	if flagged.Verify() != ErrBadFlags {
		t.Fatal("unknown flags must be rejected")
	}
}

func TestIDExcludesDateAndBindsSource(t *testing.T) {
	priv := testKey(t)
	b1, _ := Sign(priv, nil, []byte("same"), 1751700000)
	b2, _ := Sign(priv, nil, []byte("same"), 1751700042)
	id1, _ := b1.ID()
	id2, _ := b2.ID()
	if !bytes.Equal(id1, id2) {
		t.Fatal("id must exclude date (retransmits must dedup)")
	}

	b3, _ := Sign(testKey(t), nil, []byte("same"), 1751700000)
	id3, _ := b3.ID()
	if bytes.Equal(id1, id3) {
		t.Fatal("id must bind the source key")
	}
}

func TestSerializeParseRoundtripCanonical(t *testing.T) {
	priv := testKey(t)
	b, _ := Sign(priv, nil, []byte("wire"), 1751700000)

	ser, err := tl.Serialize(b, true)
	if err != nil {
		t.Fatal(err)
	}
	var parsed any
	if _, err := tl.Parse(&parsed, ser, true); err != nil {
		t.Fatal(err)
	}
	pb, ok := parsed.(Broadcast)
	if !ok {
		t.Fatalf("parsed to %T, want Broadcast", parsed)
	}
	if err := pb.Verify(); err != nil {
		t.Fatalf("parsed broadcast must verify: %v", err)
	}
	reser, err := tl.Serialize(pb, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ser, reser) {
		t.Fatal("TL re-serialization must be byte-identical (relay preserves original bytes)")
	}
}

func TestFreshWindow(t *testing.T) {
	now := time.Unix(1751700000, 0)
	if !Fresh(1751700000, now) {
		t.Fatal("now must be fresh")
	}
	if !Fresh(1751700000-60, now) || !Fresh(1751700000+60, now) {
		t.Fatal("window edges must be fresh")
	}
	if Fresh(1751700000-61, now) {
		t.Fatal("older than the window must be stale")
	}
	if Fresh(1751700000+61, now) {
		t.Fatal("newer than the window must be rejected")
	}
}
