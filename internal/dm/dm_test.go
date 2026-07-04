package dm

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSealOpenRoundTrip(t *testing.T) {
	aPub, aPriv := key(t)
	bPub, bPriv := key(t)
	msg := []byte("meet at the usual place, 21:00")

	box, err := Seal(aPriv, bPub, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(box, msg) {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := Open(bPriv, aPub, box)
	if err != nil {
		t.Fatalf("recipient should decrypt: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

func TestThirdPartyCannotOpen(t *testing.T) {
	aPub, aPriv := key(t)
	bPub, _ := key(t)
	_, evePriv := key(t)

	box, err := Seal(aPriv, bPub, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(evePriv, aPub, box); err == nil {
		t.Fatal("a third party must not decrypt a DM not addressed to it")
	}
}

func TestReflectionRejected(t *testing.T) {
	_, aPriv := key(t)
	bPub, _ := key(t)
	box, err := Seal(aPriv, bPub, []byte("did you send this?"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(aPriv, bPub, box); err == nil {
		t.Fatal("a box A sealed to B must not open as a message from B to A (reflection forgery)")
	}
}

func TestTamperDetected(t *testing.T) {
	aPub, aPriv := key(t)
	bPub, bPriv := key(t)
	box, err := Seal(aPriv, bPub, []byte("balance ok"))
	if err != nil {
		t.Fatal(err)
	}
	box[len(box)-1] ^= 0xff
	if _, err := Open(bPriv, aPub, box); err == nil {
		t.Fatal("GCM must reject a tampered ciphertext")
	}
}

func TestSharedKeyIsSymmetric(t *testing.T) {
	aPub, aPriv := key(t)
	bPub, bPriv := key(t)
	ka, err := sharedKey(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := sharedKey(bPriv, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ka, kb) {
		t.Fatal("ECDH shared key must be identical on both ends")
	}
}
