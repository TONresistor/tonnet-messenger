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
