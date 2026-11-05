package overlay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestPublicRoomsUsesExactBoxedOverlayName(t *testing.T) {
	// pub.overlay constructor, TL bytes length 22, exact name and padding.
	raw, err := hex.DecodeString("cb45ba3416746f6e6e65742d7075626c69632d726f6f6d732d763100")
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(raw)
	got, err := PublicRoomsID()
	if err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("wrong public-rooms overlay id: %x %v", got, err)
	}
}

func TestRelaysUsesExactBoxedOverlayName(t *testing.T) {
	raw, err := hex.DecodeString("cb45ba3410746f6e6e65742d72656c6179732d7631000000")
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(raw)
	got, err := RelaysID()
	if err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("wrong relays overlay id: %x %v", got, err)
	}
}

func TestInboxUsesTwoDistinctHashStages(t *testing.T) {
	inbox := make([]byte, 32)
	for i := range inbox {
		inbox[i] = byte(i)
	}
	preimage := append([]byte("tonnet-inbox"), inbox...)
	wantKey := sha256.Sum256(preimage)
	key, err := InboxKey(inbox)
	if err != nil || !bytes.Equal(key, wantKey[:]) {
		t.Fatal("wrong inbox DHT raw name", err)
	}
	// Boxed pub.overlay, 32-byte TL bytes and three padding bytes.
	raw := append([]byte{0xcb, 0x45, 0xba, 0x34, 32}, wantKey[:]...)
	raw = append(raw, 0, 0, 0)
	wantID := sha256.Sum256(raw)
	id, err := InboxID(inbox)
	if err != nil || !bytes.Equal(id, wantID[:]) || bytes.Equal(id, key) {
		t.Fatal("inbox selector used the raw name instead of boxed hash", err)
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := InboxID(bad); err == nil {
			t.Fatal("invalid inbox id length")
		}
	}
}
